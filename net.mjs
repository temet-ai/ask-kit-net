// The network as seen from this machine, for ask-kit: what a name resolves to, whether a host and
// port answer, what an HTTP(S) URL returns, what a TLS certificate says. Node built-ins only, so it
// works where dig, curl and openssl are missing. It runs no other program. Which process holds a
// local port is the procs kit.
//
// Three rules shape it. Output goes to a cloud model, so cookies, auth headers, secret-looking
// headers, URL passwords and secret-looking query values are redacted, and cloud metadata
// addresses are refused. Everything ends: every lookup, connection and request has a timeout and
// every list and body has a cap. And reading is all it does unless the caller asked for a change:
// request() sends GET, HEAD and OPTIONS always, and any other method only when `act` is true.
import dnsp from "node:dns/promises";
import nodeNet from "node:net";
import tls from "node:tls";
import http from "node:http";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { X509Certificate } from "node:crypto";

const now = () => performance.now();
const since = (t) => Math.round(now() - t);
const clamp = (v, def, min, max) => (Number.isFinite(Number(v)) && v !== null && v !== "" ? Math.min(max, Math.max(min, Number(v))) : def);
const clip = (s, n) => (String(s).length > n ? `${String(s).slice(0, n)}… [${String(s).length - n} more characters]` : String(s));
const bare = (h) => String(h ?? "").trim().replace(/^\[|\]$/g, "");

/** What an error code usually means, in plain words. */
export const MEANING = {
  ECONNREFUSED: "refused: the host answered, but nothing listens on that port (or a firewall rejects it)",
  ETIMEDOUT: "timed out: no answer at all, so the port is filtered by a firewall, the host is down, or the address is wrong",
  ENOTFOUND: "the name does not resolve (no such name, a typo, or a name only another network's DNS knows)",
  EAI_AGAIN: "the DNS server did not answer (temporary failure, or DNS is blocked from this machine)",
  EAI_NODATA: "the name exists but has no address record",
  EHOSTUNREACH: "no route to the host (wrong subnet, VPN down, or the host is off)",
  ENETUNREACH: "no route to that network (often IPv6 without an IPv6 route, or a VPN that is down)",
  ECONNRESET: "the connection was reset by the other side (a proxy, firewall or crashing server closed it)",
  EPIPE: "the other side closed the connection while data was being sent",
  EACCES: "the local system refused the connection (firewall or sandbox policy)",
  EPERM: "the local system refused the connection (firewall or sandbox policy)",
  EADDRNOTAVAIL: "no local address to connect from (no address of that family on this machine)",
  ENODATA: "the name exists but has no record of that type",
  ESERVFAIL: "the DNS server failed to answer for that name (broken zone or DNSSEC failure)",
  EREFUSED: "the DNS server refused the query",
  ETIMEOUT: "the DNS server did not answer in time (DNS blocked from this machine, or the server is down)",
  ECANCELLED: "the DNS query was stopped at the time limit (the DNS server did not answer)",
  EBADNAME: "that is not a valid DNS name",
  CERT_HAS_EXPIRED: "the certificate has expired",
  CERT_NOT_YET_VALID: "the certificate is not valid yet (or this machine's clock is wrong)",
  DEPTH_ZERO_SELF_SIGNED_CERT: "the certificate is self-signed, so nothing vouches for it",
  SELF_SIGNED_CERT_IN_CHAIN: "the chain ends in a certificate this machine does not trust (a private CA, or a proxy that re-signs TLS)",
  UNABLE_TO_VERIFY_LEAF_SIGNATURE: "the server did not send its intermediate certificate, or the issuer is unknown here",
  UNABLE_TO_GET_ISSUER_CERT_LOCALLY: "the issuer is not in this machine's trust store (private CA, or a missing intermediate)",
  UNABLE_TO_GET_ISSUER_CERT: "the issuer certificate was not found",
  ERR_TLS_CERT_ALTNAME_INVALID: "the certificate does not cover the name asked for",
  HOSTNAME_MISMATCH: "the certificate does not cover the name asked for",
  ERR_SSL_WRONG_VERSION_NUMBER: "the port does not speak TLS (plain HTTP or another protocol on this port)",
  ERR_SSL_PACKET_LENGTH_TOO_LONG: "the port does not speak TLS (plain HTTP or another protocol on this port)",
  ERR_SSL_TLSV1_ALERT_PROTOCOL_VERSION: "the server and this machine share no TLS version",
  ERR_SSL_SSLV3_ALERT_HANDSHAKE_FAILURE: "the server refused the TLS handshake (no shared cipher, or it wants a client certificate)",
  ERR_SSL_TLSV1_UNRECOGNIZED_NAME: "the server has no site for that name (SNI not known to it)",
  HPE_INVALID_CONSTANT: "the answer is not HTTP (another protocol on this port)",
  REFUSED: "refused by this kit",
};
const fail = (step, code, message) => ({ step, code: String(code ?? "ERROR"), meaning: MEANING[code] ?? clip(message ?? code, 200) });

// ---- secrets ----

const SECRET_NAME = /token|key|secret|signature|passw|pwd|credential|auth|session|cookie|^sig$/i;
const R = "<redacted>";

/** A URL safe to echo: the userinfo password and secret-looking query values replaced. Text that is not a URL is returned clipped. */
export function redactUrl(value, base) {
  let u;
  try {
    u = base ? new URL(String(value), base) : new URL(String(value));
  } catch {
    return clip(redactText(String(value)), 300);
  }
  const mark = "\u0000R\u0000";
  if (u.password) u.password = mark;
  for (const k of [...new Set(u.searchParams.keys())]) if (SECRET_NAME.test(k)) u.searchParams.set(k, mark);
  return clip(u.href.replaceAll(encodeURIComponent(mark), R).replaceAll("%00R%00", R), 400);
}

/** Free text with secret-looking values replaced: key=value and "key": "value" pairs, bearer tokens, private keys. */
export function redactText(s) {
  return String(s)
    .replace(/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(-----END [A-Z ]*PRIVATE KEY-----|$)/g, "<redacted private key>")
    .replace(/(["']?[\w.-]*(?:token|secret|passw(?:or)?d|api[_-]?key|credential|authorization|session[_-]?id|signature)[\w.-]*["']?\s*[=:]\s*)("(?:[^"\\]|\\.)*"|'[^']*'|[^\s,;&<"']+)/gi, `$1${R}`)
    .replace(/\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{8,}/g, `$1 ${R}`)
    .replace(/(\w+:\/\/[^\s/:@]+):[^\s/@]+@/g, `$1:${R}@`);
}

const cookieShape = (v) => {
  const [first, ...attrs] = String(v).split(";");
  const name = first.split("=")[0].trim();
  return clip([`${name}=${R}`, ...attrs.map((a) => a.trim()).filter(Boolean)].join("; "), 300);
};

const SHOWN = new Set(["content-type", "content-length", "content-encoding", "transfer-encoding", "location", "server", "date", "cache-control", "etag", "last-modified", "expires", "age", "via", "x-cache", "retry-after", "strict-transport-security", "set-cookie", "www-authenticate", "allow", "access-control-allow-origin", "access-control-allow-methods", "access-control-allow-headers", "x-powered-by", "x-request-id", "cf-ray", "x-served-by", "alt-svc", "connection", "upgrade", "content-disposition"]);

function showHeaders(raw, base, all) {
  const out = {};
  let hidden = 0;
  for (const [k, v] of Object.entries(raw)) {
    if (!all && !SHOWN.has(k)) {
      hidden++;
      continue;
    }
    if (Object.keys(out).length >= 40) {
      hidden++;
      continue;
    }
    if (k === "set-cookie") out[k] = [].concat(v).slice(0, 12).map(cookieShape);
    else if (k === "www-authenticate" || k === "proxy-authenticate") out[k] = [].concat(v).map((x) => `${String(x).split(/\s+/)[0]} ${R}`).join(", ");
    else if (k === "authorization" || k === "proxy-authorization" || k === "cookie" || /token|key|secret|session|passw|signature|credential/i.test(k)) out[k] = R;
    else if (k === "location" || k === "content-location" || k === "refresh" || k === "link") out[k] = k === "location" || k === "content-location" ? redactUrl(v, base) : clip(redactText(v), 300);
    else out[k] = clip(redactText([].concat(v).join(", ")), 300);
  }
  return { headers: out, hidden };
}

// ---- cloud metadata ----

const METADATA_NAMES = new Set(["metadata.google.internal", "metadata", "metadata.azure.internal", "instance-data", "instance-data.ec2.internal"]);
const METADATA_ADDRS = new Set(["169.254.169.254", "169.254.170.2", "169.254.170.23", "100.100.100.200", "fd00:ec2::254", "fd00:ec2::23"]);
const isMetadata = (host) => {
  const h = bare(host).toLowerCase().replace(/\.$/, "");
  if (METADATA_NAMES.has(h) || METADATA_ADDRS.has(h)) return true;
  const m = h.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  return !!m && METADATA_ADDRS.has(m[1]);
};
const METADATA_WHY = "is a cloud metadata address, and its answers hold credentials; net.connect(host, port) says whether it answers, without reading anything";

// ---- proxies ----

const envOf = (name) => process.env[name] || process.env[name.toLowerCase()] || "";

function noProxyHit(host, port) {
  const h = bare(host).toLowerCase();
  for (const raw of envOf("NO_PROXY").split(",").map((x) => x.trim().toLowerCase()).filter(Boolean)) {
    if (raw === "*") return raw;
    const [entry, p] = raw.includes("/") || nodeNet.isIP(raw) || raw.includes("::") ? [raw] : raw.split(":");
    if (p && Number(p) !== Number(port)) continue;
    if (entry.includes("/")) {
      const [addr, bits] = entry.split("/");
      const fam = nodeNet.isIP(addr);
      if (fam && nodeNet.isIP(h) === fam) {
        try {
          const b = new nodeNet.BlockList();
          b.addSubnet(addr, Number(bits), fam === 4 ? "ipv4" : "ipv6");
          if (b.check(h, fam === 4 ? "ipv4" : "ipv6")) return raw;
        } catch {}
      }
      continue;
    }
    const e = entry.replace(/^\*?\./, "");
    if (h === e || h.endsWith(`.${e}`)) return raw;
  }
  return null;
}

// Which proxy a URL would use, with nothing secret in it. `label` is the proxy without its userinfo.
function proxyFor(u) {
  const secure = u.protocol === "https:";
  const variable = secure ? (envOf("HTTPS_PROXY") ? "HTTPS_PROXY" : envOf("ALL_PROXY") ? "ALL_PROXY" : null) : envOf("HTTP_PROXY") ? "HTTP_PROXY" : envOf("ALL_PROXY") ? "ALL_PROXY" : null;
  if (!variable) return { used: false, via: "direct" };
  let p;
  try {
    p = new URL(envOf(variable).includes("://") ? envOf(variable) : `http://${envOf(variable)}`);
  } catch {
    return { used: false, variable, via: `direct (${variable} is set but is not a URL)` };
  }
  const label = `${p.protocol}//${p.host}`;
  const port = Number(u.port) || (secure ? 443 : 80);
  const skip = noProxyHit(u.hostname, port);
  if (skip) return { used: false, variable, proxy: label, via: `direct (NO_PROXY entry "${skip}" covers this host)` };
  if (p.protocol !== "http:") return { used: false, variable, proxy: label, via: `direct, although ${variable} is set (${label}): this kit only speaks to http:// proxies, so other tools on this machine may get a different result` };
  return {
    used: true,
    variable,
    proxy: label,
    hostname: bare(p.hostname),
    port: Number(p.port) || 80,
    tunnel: secure,
    auth: p.username ? `Basic ${Buffer.from(`${decodeURIComponent(p.username)}:${decodeURIComponent(p.password)}`).toString("base64")}` : null,
    via: `proxy ${label} (${variable}): the proxy resolved the name and made the connection, not this machine`,
  };
}

// ---- sockets ----

function tcp(address, port, ms) {
  return new Promise((resolve) => {
    const t0 = now();
    let s;
    const done = (v) => {
      clearTimeout(timer);
      resolve({ ms: since(t0), ...v });
    };
    const timer = setTimeout(() => {
      s?.destroy();
      done({ code: "ETIMEDOUT" });
    }, ms);
    try {
      s = nodeNet.connect({ host: address, port, autoSelectFamily: false });
    } catch (e) {
      return done({ code: e.code ?? "ERROR", message: e.message });
    }
    s.once("connect", () => done({ socket: s }));
    s.on("error", (e) => done({ code: e.code ?? "ERROR", message: e.message }));
  });
}

async function sysLookup(host, ms = 5000) {
  const h = bare(host);
  const fam = nodeNet.isIP(h);
  if (fam) return { addresses: [{ address: h, family: fam }] };
  let timer;
  try {
    const addresses = await Promise.race([
      dnsp.lookup(h, { all: true, order: "verbatim" }),
      new Promise((_, rej) => {
        timer = setTimeout(() => rej(Object.assign(new Error("lookup timed out"), { code: "EAI_AGAIN" })), ms);
      }),
    ]);
    return { addresses };
  } catch (e) {
    return { addresses: [], code: e.code ?? "ERROR", message: e.message };
  } finally {
    clearTimeout(timer);
  }
}

function handshake(socket, servername, ms) {
  return new Promise((resolve) => {
    const done = (v) => {
      clearTimeout(timer);
      resolve(v);
    };
    const timer = setTimeout(() => {
      socket.destroy();
      done({ code: "ETIMEDOUT", message: "TLS handshake did not finish" });
    }, ms);
    // The chain is checked by hand afterwards, so a bad certificate can be described instead of only failing.
    const s = tls.connect({ socket, servername: nodeNet.isIP(servername) ? undefined : servername, rejectUnauthorized: false, ALPNProtocols: ["http/1.1"] });
    s.once("secureConnect", () => done({ socket: s }));
    s.on("error", (e) => done({ code: e.code ?? "ERROR", message: e.message }));
    socket.once("close", () => done({ code: "ECONNRESET", message: "closed during the TLS handshake" }));
  });
}

// CONNECT through an http proxy. Resolves to {} or {error}.
function tunnel(socket, host, port, auth, ms, label) {
  return new Promise((resolve) => {
    let buf = Buffer.alloc(0);
    const done = (v) => {
      clearTimeout(timer);
      socket.removeListener("data", onData);
      resolve(v);
    };
    const timer = setTimeout(() => done({ error: fail("proxy", "ETIMEDOUT", `the proxy ${label} did not answer CONNECT`) }), ms);
    const onData = (d) => {
      buf = Buffer.concat([buf, d]);
      const end = buf.indexOf("\r\n\r\n");
      if (end < 0 && buf.length < 16384) return;
      const head = buf.subarray(0, end < 0 ? buf.length : end).toString("latin1");
      const rest = end < 0 ? Buffer.alloc(0) : buf.subarray(end + 4);
      const m = head.match(/^HTTP\/\d\.\d (\d{3})([^\r\n]*)/);
      if (m?.[1] === "200") {
        if (rest.length) socket.unshift(rest);
        return done({});
      }
      const why = [m ? `${m[1]}${m[2]}` : "not an HTTP answer", clip(redactText(rest.toString("utf8").replace(/\s+/g, " ").trim()), 200)].filter(Boolean).join(": ");
      const meaning = m?.[1] === "403" ? "the proxy refused this host (not allowed by its policy)" : m?.[1] === "407" ? "the proxy wants credentials" : m?.[1] === "502" || m?.[1] === "503" || m?.[1] === "504" ? "the proxy could not reach the host (it does not resolve there, refuses, or times out)" : "the proxy did not open a tunnel";
      done({ error: { step: "proxy", code: `PROXY_${m?.[1] ?? "BAD"}`, meaning, message: `CONNECT ${host}:${port} via ${label} answered ${why}` } });
    };
    socket.on("data", onData);
    socket.once("close", () => done({ error: fail("proxy", "ECONNRESET", `the proxy ${label} closed the connection during CONNECT`) }));
    const hp = `${host.includes(":") ? `[${host}]` : host}:${port}`;
    socket.write(`CONNECT ${hp} HTTP/1.1\r\nHost: ${hp}\r\n${auth ? `Proxy-Authorization: ${auth}\r\n` : ""}\r\n`);
  });
}

// A connected (and for `secure`, TLS) socket to host:port, direct or through a proxy, with the time each step took.
async function open({ host, port, secure, proxy, ms, guard }) {
  const t0 = now();
  const timing = { dns: null, connect: null, tls: null };
  const out = { timing, via: proxy?.via ?? "direct" };
  const left = () => Math.max(1, ms - (now() - t0));
  let socket;
  if (proxy?.used) {
    const r = await tcp(proxy.hostname, proxy.port, left());
    if (!r.socket) return { ...out, error: { ...fail("proxy", r.code, r.message), message: `could not connect to the proxy ${proxy.proxy}` } };
    r.socket.on("error", () => {});
    if (proxy.tunnel) {
      const c = await tunnel(r.socket, host, port, proxy.auth, left(), proxy.proxy);
      if (c.error) {
        r.socket.destroy();
        return { ...out, error: c.error };
      }
    }
    socket = r.socket;
    timing.connect = since(t0);
  } else {
    const l = await sysLookup(host, Math.min(left(), 5000));
    timing.dns = since(t0);
    if (!l.addresses.length) return { ...out, error: fail("dns", l.code, l.message) };
    if (guard && l.addresses.some((a) => isMetadata(a.address))) return { ...out, error: { step: "refused", code: "REFUSED", meaning: `${host} resolves to ${l.addresses.map((a) => a.address).join(", ")}, which ${METADATA_WHY}` } };
    const tc = now();
    const tried = [];
    const list = l.addresses.slice(0, 4);
    for (const a of list) {
      const r = await tcp(a.address, port, list.length > 1 ? Math.min(left(), 3000) : left());
      if (r.socket) {
        socket = r.socket;
        out.address = a.address;
        break;
      }
      tried.push({ address: a.address, code: r.code });
      if (left() <= 1) break;
    }
    timing.connect = since(tc);
    if (tried.length) out.failedAddresses = tried;
    if (!socket) return { ...out, error: { ...fail("tcp", tried.at(-1).code), message: tried.map((a) => `${a.address}:${port} ${a.code}`).join(", ") } };
    socket.on("error", () => {});
  }
  if (secure) {
    const th = now();
    const h = await handshake(socket, host, left());
    timing.tls = since(th);
    if (!h.socket) {
      socket.destroy();
      return { ...out, error: fail("tls", h.code, h.message) };
    }
    socket = h.socket;
  }
  return { ...out, socket };
}

// ---- certificates ----

const dn = (s) => String(s ?? "").split("\n").filter(Boolean).join(", ");
const DAY = 86_400_000;
// The moment certificates are judged by: now, or the date a caller passes (a bench must not change with the calendar).
const moment = (v) => {
  if (v == null || v === "") return Date.now();
  const t = typeof v === "number" ? v : Date.parse(v);
  if (!Number.isFinite(t)) throw new Error(`net.cert: now must be a date such as "2026-01-15", not "${v}"`);
  return t;
};

function describeCert(x, name, at = Date.now()) {
  const from = new Date(x.validFrom);
  const to = new Date(x.validTo);
  const sansAll = String(x.subjectAltName ?? "").split(/,\s*/).filter(Boolean).map((s) => s.replace(/^DNS:/, "").replace(/^IP Address:/, "IP:"));
  let selfSigned = x.subject === x.issuer;
  if (selfSigned) {
    try {
      selfSigned = x.verify(x.publicKey);
    } catch {}
  }
  const daysLeft = Math.floor((to - at) / DAY);
  const k = x.publicKey;
  const d = {
    subject: dn(x.subject),
    commonName: String(x.subject ?? "").match(/^CN=(.*)$/m)?.[1] ?? null,
    sans: sansAll.slice(0, 40),
    ...(sansAll.length > 40 ? { moreSans: sansAll.length - 40 } : {}),
    issuer: dn(x.issuer),
    validFrom: from.toISOString(),
    validTo: to.toISOString(),
    daysLeft,
    expired: to < at,
    notYetValid: from > at,
    selfSigned,
    key: `${k.asymmetricKeyType}${k.asymmetricKeyDetails?.modulusLength ? ` ${k.asymmetricKeyDetails.modulusLength}` : k.asymmetricKeyDetails?.namedCurve ? ` ${k.asymmetricKeyDetails.namedCurve}` : ""}`,
    fingerprint256: x.fingerprint256,
  };
  if (name) {
    const n = bare(name);
    d.nameAsked = n;
    d.coversName = nodeNet.isIP(n) ? !!x.checkIP(n) : !!x.checkHost(n);
  }
  return d;
}

// The findings a person would act on, worst first. An empty list means nothing is wrong with it.
function certProblems(d) {
  const p = [];
  if (d.expired) p.push(`expired ${-d.daysLeft} days ago (${d.validTo.slice(0, 10)})`);
  else if (d.notYetValid) p.push(`not valid until ${d.validFrom.slice(0, 10)}`);
  else if (d.daysLeft < 14) p.push(`expires in ${d.daysLeft} days (${d.validTo.slice(0, 10)})`);
  if (d.coversName === false) p.push(`name mismatch: it does not cover ${d.nameAsked} (it covers ${d.sans.slice(0, 6).join(", ") || d.commonName})`);
  if (d.selfSigned) p.push("self-signed");
  else if (d.chainVerifies === null && d.chainNote) p.push(`chain not checked: ${d.chainNote}`);
  else if (d.chainVerifies === false) p.push(`chain does not verify: ${d.verifyError ? `${d.verifyError}, ` : ""}${d.chainNote ?? ""}`.trim());
  return p;
}

let rootsCache;
const roots = () => {
  if (!rootsCache) {
    rootsCache = [];
    let pems = [];
    try {
      pems = tls.getCACertificates ? tls.getCACertificates("default") : tls.rootCertificates;
    } catch {
      pems = tls.rootCertificates;
    }
    for (const pem of pems) {
      try {
        rootsCache.push(new X509Certificate(pem));
      } catch {}
    }
  }
  return rootsCache;
};
const issuedBy = (child, parent) => {
  try {
    return child.checkIssued(parent) && child.verify(parent.publicKey);
  } catch {
    return false;
  }
};

// The public CAs Node ships with. A chain that verifies but ends elsewhere was issued by a private CA
// this machine was told to trust: a company CA, a local development CA, or a proxy that re-signs TLS.
let publicCache;
const publicRoots = () => (publicCache ??= tls.rootCertificates.flatMap((pem) => {
  try {
    return [new X509Certificate(pem)];
  } catch {
    return [];
  }
}));
// The top of a presented chain is a public root itself, or (a cross-signed root) carries one's name, or is signed by one.
const isPublic = (top) => publicRoots().some((r) => r.fingerprint256 === top.fingerprint256 || r.subject === top.subject || (r.subject === top.issuer && issuedBy(top, r)));
const link = (x, at) => ({ subject: dn(x.subject), issuer: dn(x.issuer), validTo: new Date(x.validTo).toISOString(), daysLeft: Math.floor((new Date(x.validTo) - at) / DAY) });

function peerInfo(s, name, { at = Date.now(), viaProxy = false } = {}) {
  // The chain is read before the leaf: once getPeerX509Certificate() was called, Node returns an empty chain.
  const xs = [];
  const seen = new Set();
  for (let c = s.getPeerCertificate(true); c?.raw && !seen.has(c.fingerprint256) && xs.length < 8; c = c.issuerCertificate) {
    seen.add(c.fingerprint256);
    try {
      xs.push(new X509Certificate(c.raw));
    } catch {}
  }
  if (!xs.length) return null;
  const d = describeCert(xs[0], name, at);
  // With a chain error Node skips the name check, so the name is checked here in every case.
  const code = s.authorizationError ? String(s.authorizationError.code ?? s.authorizationError) : null;
  const chainCode = code && code !== "ERR_TLS_CERT_ALTNAME_INVALID" ? code : null;
  d.chainVerifies = !chainCode;
  if (chainCode) {
    d.verifyError = chainCode;
    d.chainNote = MEANING[chainCode] ?? chainCode;
  } else if (!isPublic(xs.at(-1))) {
    d.privateCA = dn(xs.at(-1).subject);
    if (viaProxy) {
      d.intercepted = true;
      d.chainNote = `this is the proxy's certificate, not the site's: the request went through a proxy that re-signs TLS with its own CA (${d.privateCA}), which this machine is set to trust. The site's own certificate, its issuer and its expiry cannot be seen from this machine`;
    } else d.chainNote = `issued by a private CA (${d.privateCA}) that this machine is set to trust; other machines will not trust it`;
  }
  d.protocol = s.getProtocol();
  d.cipher = s.getCipher()?.name ?? null;
  if (xs.length > 1) d.chain = xs.map((x) => link(x, at));
  d.problems = certProblems(d);
  return d;
}

// ---- the global ----

const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);
const DNS_TYPES = ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA"];
const TEXT_TYPE = /^(text\/|application\/(json|xml|javascript|ecmascript|x-www-form-urlencoded|x-ndjson|x-yaml|yaml|[\w.+-]*\+(json|xml)))/i;

export function make({ settings = {}, push = () => {}, act = false } = {}) {
  const workdir = settings.WORKDIR || process.cwd();
  const note = (kind, detail, t0, code, size) => push({ kind, detail: clip(detail, 200), ms: since(t0), code, size });

  /**
   * What a name resolves to, two ways: `system` is what programs on this machine get (hosts file, then DNS, as getaddrinfo answers)
   * and `dns` is what the DNS servers say per record type. For an address, the PTR names.
   */
  async function resolve(name, o = {}) {
    if (!name) throw new Error("net.resolve needs a name or an address, e.g. net.resolve('example.com')");
    const t0 = now();
    const n = bare(String(name).replace(/^\w+:\/\//, "").replace(/[/?#].*$/, "").replace(/^[^@/]*@/, "").replace(/:\d+$/, "")).replace(/\.$/, "");
    const ms = clamp(o.timeoutMs, 5000, 200, 20000);
    const r = new dnsp.Resolver({ timeout: Math.max(200, Math.floor(ms / 3)), tries: 2 });
    if (o.server) {
      try {
        r.setServers([String(o.server)]);
      } catch {
        throw new Error(`net.resolve: server must be an IP address such as "1.1.1.1" or "[2606:4700:4700::1111]:53", not "${o.server}"`);
      }
    }
    const servers = r.getServers();
    const timer = setTimeout(() => r.cancel(), ms);
    const out = { name: n, servers };
    try {
      if (nodeNet.isIP(n)) {
        out.kind = "address";
        try {
          out.ptr = await r.reverse(n);
        } catch (e) {
          out.ptr = [];
          out.error = { code: e.code, meaning: MEANING[e.code] ?? e.message };
        }
        note("dns", `reverse ${n}`, t0, out.error?.code ?? 0);
        out.note = out.ptr.length ? `${n} is ${out.ptr.join(", ")}` : `no PTR name for ${n}${out.error ? `: ${out.error.meaning}` : ""}`;
        return out;
      }
      const asked = [].concat(typeof o.types === "string" ? o.types.split(/[,\s]+/) : o.types ?? ["A", "AAAA", "CNAME"]).map((t) => String(t).toUpperCase()).filter(Boolean);
      const types = asked.includes("ALL") || asked.includes("ANY") ? DNS_TYPES : asked;
      const bad = types.filter((t) => !DNS_TYPES.includes(t));
      if (bad.length) throw new Error(`net.resolve: unknown record type ${bad.join(", ")}; have: ${DNS_TYPES.join(", ")}, or "all" (PTR: pass an address as the name)`);
      const sys = await sysLookup(n, ms);
      out.system = sys.addresses.length ? { addresses: sys.addresses.map((a) => a.address) } : { addresses: [], error: sys.code, meaning: MEANING[sys.code] ?? sys.message };
      try {
        const hits = fs.readFileSync("/etc/hosts", "utf8").split("\n").map((l) => l.replace(/#.*/, "").trim()).filter((l) => l.split(/\s+/).slice(1).some((h) => h.toLowerCase() === n.toLowerCase()));
        if (hits.length) out.hostsFile = hits.slice(0, 5);
      } catch {}
      const records = {};
      const errors = {};
      await Promise.all(
        types.map(async (t) => {
          try {
            const v = t === "SOA" ? [await r.resolveSoa(n)] : await r.resolve(n, t);
            records[t] = (t === "TXT" ? v.map((parts) => clip(redactText(parts.join("")), 300)) : t === "MX" ? v.sort((a, b) => a.priority - b.priority).map((m) => `${m.priority} ${m.exchange}`) : v).slice(0, 20);
            if (v.length > 20) records[`${t}_more`] = v.length - 20;
          } catch (e) {
            if (e.code === "ENODATA") records[t] = [];
            else errors[t] = e.code ?? "ERROR";
          }
        }),
      );
      const codes = [...new Set(Object.values(errors))];
      const unreachable = types.length > 0 && Object.keys(errors).length === types.length && codes.every((c) => ["ETIMEOUT", "ECONNREFUSED", "ECANCELLED", "EREFUSED"].includes(c));
      out.dns = { records, ...(codes.length ? { errors, meaning: codes.map((c) => `${c}: ${MEANING[c] ?? c}`).join("; ") } : {}), ...(unreachable ? { unreachable: true } : {}) };
      const dnsAddrs = [...(records.A ?? []), ...(records.AAAA ?? [])];
      const sysAddrs = out.system.addresses;
      const askedAddrs = types.includes("A") || types.includes("AAAA");
      if (unreachable) {
        out.differ = null;
        out.note = `the DNS servers (${servers.join(", ")}) did not answer from this machine, so only the system resolver's answer is known${sysAddrs.length ? "" : "; it failed too"}${envOf("HTTPS_PROXY") ? "; a proxy is set, and it may be the only thing here that can resolve public names" : ""}`;
      } else if (!askedAddrs) out.differ = null;
      else {
        const onlySys = sysAddrs.filter((a) => !dnsAddrs.includes(a));
        const fams = new Set(types.filter((t) => t === "A" || t === "AAAA"));
        const onlySysAsked = onlySys.filter((a) => fams.has(nodeNet.isIP(a) === 4 ? "A" : "AAAA"));
        out.differ = onlySysAsked.length > 0 || (sysAddrs.length === 0 && dnsAddrs.length > 0);
        if (onlySysAsked.length) out.note = `programs on this machine get ${onlySysAsked.join(", ")}, which DNS (${servers.join(", ")}) does not say${out.hostsFile ? `: the hosts file sets it (${out.hostsFile[0]})` : ": a hosts file entry, mDNS, a local resolver or split DNS"}`;
        else if (out.differ) out.note = `DNS says ${dnsAddrs.join(", ")} but the system resolver fails (${out.system.error})`;
        else if (!sysAddrs.length && !dnsAddrs.length) out.note = `${n} does not resolve: ${out.system.meaning}`;
      }
      note("dns", `resolve ${n} ${types.join(",")}`, t0, sysAddrs.length || dnsAddrs.length ? 0 : (out.system.error ?? 1));
      return out;
    } finally {
      clearTimeout(timer);
    }
  }

  /** A TCP connection to each address a host resolves to, with the milliseconds it took or the error code and what it means. */
  async function connect(host, port, o = {}) {
    let h = bare(host);
    let p = port;
    const hp = p == null && !nodeNet.isIP(h) ? String(host).match(/^\[?([^\]]+?)\]?:(\d+)$/) : null;
    if (hp) [h, p] = [hp[1], hp[2]];
    p = Number(p);
    if (!h || !Number.isInteger(p) || p < 1 || p > 65535) throw new Error("net.connect needs a host and a port from 1 to 65535, e.g. net.connect('example.com', 443)");
    const ms = clamp(o.timeoutMs, 3000, 100, 20000);
    const t0 = now();
    const l = await sysLookup(h, 5000);
    const out = { host: h, port: p, via: "direct", resolved: l.addresses.map((a) => a.address), attempts: [], open: false };
    if (!l.addresses.length) {
      out.error = fail("dns", l.code, l.message);
      note("tcp", `connect ${h}:${p}`, t0, l.code);
      return out;
    }
    const list = l.addresses.slice(0, 6);
    if (l.addresses.length > 6) out.moreAddresses = l.addresses.length - 6;
    out.attempts = await Promise.all(
      list.map(async (a) => {
        const r = await tcp(a.address, p, ms);
        r.socket?.destroy();
        return r.socket ? { address: a.address, family: a.family, open: true, ms: r.ms } : { address: a.address, family: a.family, open: false, ms: r.ms, code: r.code, meaning: MEANING[r.code] ?? r.message ?? r.code };
      }),
    );
    out.open = out.attempts.some((a) => a.open);
    const px = envOf("HTTPS_PROXY") || envOf("HTTP_PROXY") || envOf("ALL_PROXY");
    if (px && !out.open && !noProxyHit(h, p)) out.proxyNote = "a proxy variable is set on this machine: this was a direct connection, and tools that use the proxy (curl, npm, git) may reach the host although this could not";
    note("tcp", `connect ${h}:${p}`, t0, out.open ? 0 : out.attempts[0]?.code);
    return out;
  }

  // One request, no redirects followed.
  async function hop(u, { method, headers, body, ms, bodyBytes, allHeaders, insecure, readBody }) {
    const t0 = now();
    const secure = u.protocol === "https:";
    const host = bare(u.hostname);
    const port = Number(u.port) || (secure ? 443 : 80);
    const shown = redactUrl(u.href);
    // realUrl and rawLocation are for request() to follow redirects; it deletes them before returning.
    const h = { url: shown, realUrl: u.href };
    if (isMetadata(host)) return { ...h, error: { step: "refused", code: "REFUSED", meaning: `${host} ${METADATA_WHY}` } };
    const proxy = proxyFor(u);
    const c = await open({ host, port, secure, proxy, ms, guard: true });
    h.timing = { ...c.timing, firstByte: null, total: null };
    if (c.address) h.address = c.address;
    h.via = c.via;
    if (c.failedAddresses) h.failedAddresses = c.failedAddresses;
    const finish = (extra) => {
      h.timing.total = since(t0);
      Object.assign(h, extra);
      note("http", `${method} ${shown}`, t0, h.status ?? h.error?.code, h.body?.bytes);
      return h;
    };
    if (c.error) return finish({ error: c.error });
    const socket = c.socket;
    if (secure) {
      const t = peerInfo(socket, host, { viaProxy: !!proxy.used });
      if (t) {
        h.tls = { protocol: t.protocol, subject: t.commonName ?? t.subject, issuer: t.issuer, validTo: t.validTo, daysLeft: t.daysLeft, coversName: t.coversName, chainVerifies: t.chainVerifies, ...(t.verifyError ? { verifyError: t.verifyError } : {}), ...(t.intercepted ? { intercepted: true } : {}), ...(t.chainNote ? { note: t.chainNote } : {}), problems: t.problems };
        const blocking = !t.chainVerifies || t.coversName === false || t.expired || t.notYetValid;
        if (blocking && !insecure) {
          socket.destroy();
          const code = t.expired ? "CERT_HAS_EXPIRED" : t.verifyError ?? (t.coversName === false ? "HOSTNAME_MISMATCH" : "CERT_NOT_YET_VALID");
          return finish({ error: { step: "tls", code, meaning: `the certificate was not accepted, so no request was sent: ${t.problems.join("; ") || MEANING[code]}`, hint: "net.cert(host, port) shows the whole certificate; {insecure: true} sends the request anyway" } });
        }
      }
    }
    return new Promise((resolve) => {
      let settled = false;
      const end = (extra) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        socket.destroy();
        resolve(finish(extra));
      };
      const hdrs = { host: u.host, "user-agent": "ask-kit-net/0.1", accept: "*/*", "accept-encoding": "identity", connection: "close" };
      if (u.username) hdrs.authorization = `Basic ${Buffer.from(`${decodeURIComponent(u.username)}:${decodeURIComponent(u.password)}`).toString("base64")}`;
      for (const [k, v] of Object.entries(headers ?? {})) hdrs[String(k).toLowerCase()] = String(v);
      const payload = body == null ? null : Buffer.from(typeof body === "string" ? body : JSON.stringify(body));
      if (payload) {
        hdrs["content-length"] = String(payload.length);
        if (!hdrs["content-type"]) hdrs["content-type"] = typeof body === "string" ? "text/plain; charset=utf-8" : "application/json";
      }
      const forward = proxy.used && !proxy.tunnel;
      if (forward && proxy.auth) hdrs["proxy-authorization"] = proxy.auth;
      const clean = new URL(u.href);
      clean.username = clean.password = "";
      clean.hash = "";
      let req;
      let partial = null;
      const timer = setTimeout(() => {
        if (partial) return end(partial("the body stopped arriving before the time limit"));
        end({ error: { step: "http", code: "ETIMEDOUT", meaning: `connected${secure ? " and TLS was set up" : ""}, but no response came within ${ms} ms: the server is slow, hung, or waiting for something` } });
      }, Math.max(1, ms - (now() - t0)));
      try {
        // With createConnection and no agent option, Node uses the socket given and opens none of its own.
        req = http.request({ createConnection: () => socket, method, path: forward ? clean.href : `${u.pathname}${u.search}`, headers: hdrs, setHost: false });
      } catch (e) {
        return end({ error: fail("http", e.code ?? "ERROR", e.message) });
      }
      req.on("error", (e) => end({ error: fail("http", e.code ?? "ERROR", e.message) }));
      req.on("response", (res) => {
        h.timing.firstByte = since(t0);
        h.status = res.statusCode;
        h.rawLocation = res.headers.location ?? null;
        const sh = showHeaders(res.headers, u.href, allHeaders);
        h.headers = sh.headers;
        if (sh.hidden) h.headersNotShown = sh.hidden;
        const type = String(res.headers["content-type"] ?? "");
        const enc = String(res.headers["content-encoding"] ?? "").toLowerCase();
        const length = res.headers["content-length"] != null ? Number(res.headers["content-length"]) : null;
        if (!readBody || method === "HEAD" || res.statusCode === 204 || res.statusCode === 304) return end({});
        const limit = Math.max(bodyBytes * 4, 2048);
        const chunks = [];
        let got = 0;
        const describe = (complete, stalled) => {
          const buf = Buffer.concat(chunks);
          const b = { type: type || null, bytes: complete ? got : length ?? null, ...(complete ? {} : { bytesRead: got }) };
          if (enc && enc !== "identity") {
            return { body: { ...b, encoding: enc, note: `${enc}-encoded body, not decoded` } };
          }
          const isText = type ? TEXT_TYPE.test(type) : !buf.subarray(0, 512).includes(0);
          if (!isText || buf.subarray(0, 512).includes(0)) return { body: { ...b, binary: true, note: `binary body (${type || "no content-type"}), not shown` } };
          if (!bodyBytes) return { body: { ...b, note: "body not read (max: 0)" } };
          let text;
          try {
            text = new TextDecoder(type.match(/charset=([\w-]+)/i)?.[1] ?? "utf-8").decode(buf);
          } catch {
            text = buf.toString("utf8");
          }
          const cut = text.length > bodyBytes || !complete;
          b.text = redactText(text.slice(0, bodyBytes));
          if (cut) b.truncated = stalled ?? `the first ${Math.min(text.length, bodyBytes)} characters${length != null ? ` of ${length} bytes` : ""}`;
          return { body: b };
        };
        partial = (why) => describe(false, why);
        res.on("data", (d) => {
          chunks.push(d);
          got += d.length;
          if (got >= limit) end(describe(false));
        });
        res.on("end", () => end(describe(true)));
        res.on("error", (e) => end({ ...describe(false, `the body broke off: ${e.code ?? e.message}`) }));
      });
      req.end(payload ?? undefined);
    });
  }

  /**
   * What a URL returns: each hop of the redirect chain with status, headers, timing, and the final body's first part.
   * GET, HEAD and OPTIONS always; another method only when the caller asked for a change.
   */
  async function request(url, o = {}) {
    if (!url) throw new Error("net.request needs a URL, e.g. net.request('https://example.com/health')");
    let u;
    try {
      u = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(String(url)) ? String(url) : `http://${url}`);
    } catch {
      throw new Error(`net.request: "${clip(redactText(url), 120)}" is not a URL; give one like https://example.com/path`);
    }
    if (!/^https?:$/.test(u.protocol)) throw new Error(`net.request speaks http and https only, not ${u.protocol}; for another protocol use net.connect(host, port) to see whether the port answers, and net.cert(host, port) for its TLS certificate`);
    const method = String(o.method ?? "GET").toUpperCase();
    if (!/^[A-Z]+$/.test(method)) throw new Error(`net.request: "${method}" is not an HTTP method`);
    if (!SAFE_METHODS.has(method) && !act) throw new Error(`not in this ask: net.request with ${method} changes things, and the caller did not ask for a change (act: true), so nothing was sent. GET, HEAD and OPTIONS work without it. Say that this needs \`ask\` with act: true; do not look for another way to do it.`);
    if (isMetadata(u.hostname)) throw new Error(`not allowed: ${bare(u.hostname)} ${METADATA_WHY}`);
    if (o.body != null && SAFE_METHODS.has(method)) throw new Error(`net.request: a body goes with POST, PUT or PATCH, not ${method}`);
    const ms = clamp(o.timeoutMs, 10000, 200, 60000);
    const maxRedirects = clamp(o.redirects, 5, 0, 10);
    const follow = o.follow !== false && SAFE_METHODS.has(method);
    const opts = { method, headers: { ...(o.headers ?? {}) }, body: o.body, ms, bodyBytes: clamp(o.max, 2048, 0, 16384), allHeaders: !!o.allHeaders, insecure: !!o.insecure };
    const hops = [];
    const t0 = now();
    for (;;) {
      const loc = (s) => s >= 300 && s < 400 && s !== 304;
      const h = await hop(u, { ...opts, readBody: true });
      let to;
      hops.push(h);
      if (!h.status || !loc(h.status) || !follow) break;
      const raw = h.rawLocation;
      if (!raw) break;
      try {
        to = new URL(raw, u.href);
      } catch {
        h.note = "the Location header is not a URL";
        break;
      }
      if (!/^https?:$/.test(to.protocol)) {
        h.note = `redirects to ${to.protocol} which is not followed`;
        break;
      }
      if (hops.length > maxRedirects) {
        h.note = `stopped after ${maxRedirects} redirects; the chain goes on`;
        break;
      }
      if (hops.some((x) => x.realUrl === to.href) || to.href === u.href) {
        h.note = "redirect loop: this URL was already visited";
        break;
      }
      if (to.host !== u.host) for (const k of Object.keys(opts.headers)) if (/^(authorization|cookie|proxy-authorization)$/i.test(k)) delete opts.headers[k];
      u = to;
    }
    for (const h of hops) {
      delete h.rawLocation;
      delete h.realUrl;
      if (h !== hops.at(-1)) delete h.body;
    }
    const last = hops.at(-1);
    const out = {
      url: hops[0].url,
      method,
      ok: !!last.status && last.status < 400 && !last.error && !last.note,
      status: last.status ?? null,
      redirects: hops.length - 1,
      finalUrl: last.url,
      totalMs: since(t0),
      hops,
    };
    if (last.error) out.error = last.error;
    delete last.error;
    if (last.body && (last.body.bytes || last.body.bytesRead || last.body.note)) out.body = last.body;
    delete last.body;
    const sent = Object.keys(o.headers ?? {});
    if (sent.length) out.sentHeaderNames = sent;
    if (!SAFE_METHODS.has(method) && last.status >= 300 && last.status < 400) out.note = `${method} requests are not followed through redirects; the server points to ${last.headers?.location}`;
    return out;
  }

  /**
   * The TLS certificate a server presents (host, port) or one in a PEM or DER file ({file}): subject, names covered,
   * issuer, validity, days left, self-signed or not, whether the chain verifies and why not, protocol and cipher.
   */
  async function cert(a, b, c) {
    const first = a && typeof a === "object" ? a : null;
    const o = first ?? (b && typeof b === "object" ? b : c ?? {});
    if (first?.file || (typeof a === "string" && /\.(pem|crt|cer|der)$/i.test(a) && fs.existsSync(path.resolve(workdir, a)))) return certFile(first?.file ?? a, o);
    let host = first?.host ?? a;
    let port = first?.port ?? (typeof b === "object" ? undefined : b);
    if (!host) throw new Error("net.cert needs a host (net.cert('example.com'), net.cert('example.com', 8443)) or a file (net.cert({file: 'server.pem'}))");
    host = String(host);
    if (/^[a-z][a-z0-9+.-]*:\/\//i.test(host)) {
      const u = new URL(host);
      host = u.hostname;
      port ??= u.port || undefined;
    } else {
      const m = !nodeNet.isIP(bare(host)) && host.match(/^\[?([^\]]+?)\]?:(\d+)$/);
      if (m) [host, port] = [m[1], port ?? m[2]];
    }
    host = bare(host);
    port = Number(port ?? 443);
    if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error("net.cert: the port must be a number from 1 to 65535");
    const name = bare(o.servername ?? host);
    const ms = clamp(o.timeoutMs, 8000, 200, 30000);
    const at = moment(o.now);
    const t0 = now();
    const proxy = proxyFor(new URL(`https://${host.includes(":") ? `[${host}]` : host}:${port}/`));
    const s = await open({ host, port, secure: false, proxy, ms });
    const out = { source: `${host}:${port}`, servername: name, via: s.via };
    if (s.address) out.address = s.address;
    if (s.error) {
      note("tls", `cert ${host}:${port}`, t0, s.error.code);
      return { ...out, error: s.error };
    }
    const h = await handshake(s.socket, name, Math.max(1, ms - (now() - t0)));
    if (!h.socket) {
      s.socket.destroy();
      note("tls", `cert ${host}:${port}`, t0, h.code);
      const starttls = { 25: "SMTP", 587: "SMTP", 143: "IMAP", 110: "POP3", 5432: "PostgreSQL", 3306: "MySQL", 21: "FTP" }[port];
      return { ...out, error: { ...fail("tls", h.code, h.message), ...(starttls ? { hint: `port ${port} is usually ${starttls}, which starts in plain text and upgrades to TLS (STARTTLS); this kit only reads certificates from ports that speak TLS from the first byte` } : {}) } };
    }
    const info = peerInfo(h.socket, name, { at, viaProxy: !!proxy.used });
    h.socket.destroy();
    note("tls", `cert ${host}:${port}`, t0, 0);
    if (!info) return { ...out, error: { step: "tls", code: "NO_CERT", meaning: "the server completed TLS without presenting a certificate" } };
    return { ...out, ...info };
  }

  function certFile(file, o = {}) {
    const t0 = now();
    const at = moment(o.now);
    const full = path.resolve(workdir, String(file).replace(/^~(?=$|[\\/])/, os.homedir()));
    const out = { source: full };
    let buf;
    try {
      const st = fs.statSync(full);
      if (st.size > 1 << 20) return { ...out, error: { step: "file", code: "TOO_BIG", meaning: `the file is ${st.size} bytes; a certificate file is a few KB` } };
      buf = fs.readFileSync(full);
    } catch (e) {
      note("file", `cert ${full}`, t0, e.code);
      return { ...out, error: { step: "file", code: e.code ?? "ERROR", meaning: e.code === "ENOENT" ? `no file at ${full} (relative paths start from ${workdir})` : e.message } };
    }
    note("file", `cert ${full}`, t0, 0, buf.length);
    const text = buf.toString("latin1");
    const blocks = text.match(/-----BEGIN (?:TRUSTED )?CERTIFICATE-----[\s\S]*?-----END (?:TRUSTED )?CERTIFICATE-----/g) ?? [];
    const hasKey = /-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(text);
    const certs = [];
    for (const blk of blocks.slice(0, 10)) {
      try {
        certs.push(new X509Certificate(blk));
      } catch {}
    }
    if (!certs.length && !hasKey && !text.includes("-----BEGIN")) {
      try {
        certs.push(new X509Certificate(buf));
      } catch {}
    }
    if (!certs.length) return { ...out, error: { step: "file", code: "NO_CERT", meaning: hasKey ? "the file holds a private key and no certificate; nothing in it was shown" : "no certificate found in the file (expected PEM with -----BEGIN CERTIFICATE----- or DER)" } };
    const d = describeCert(certs[0], o.name ?? o.servername, at);
    const chain = certs.map((x) => link(x, at));
    let ok = true;
    let why = null;
    for (let i = 0; i + 1 < certs.length && ok; i++) {
      if (!issuedBy(certs[i], certs[i + 1])) {
        ok = false;
        why = `certificate ${i + 1} in the file is not signed by certificate ${i + 2}`;
      }
    }
    const top = certs.at(-1);
    if (ok) {
      if (d.selfSigned && certs.length === 1) [ok, why] = [false, "self-signed: it is its own issuer"];
      else {
        const root = roots().find((r) => r.fingerprint256 === top.fingerprint256 || (r.subject === top.issuer && issuedBy(top, r)));
        if (root) why = `chains to ${dn(root.subject)} in this machine's trust store`;
        else [ok, why] = [top.subject === top.issuer ? false : null, top.subject === top.issuer ? "the file's root is not in this machine's trust store" : `the issuer (${dn(top.issuer)}) is not in the file or in this machine's trust store, so the chain could not be checked`];
      }
    }
    const expiredInChain = chain.findIndex((x, i) => i > 0 && x.daysLeft < 0);
    if (ok && expiredInChain > 0) [ok, why] = [false, `certificate ${expiredInChain + 1} in the file has expired`];
    d.chainVerifies = ok;
    d.chainNote = why;
    if (certs.length > 1) d.chain = chain;
    if (blocks.length > 10) d.moreCertificates = blocks.length - 10;
    if (hasKey) d.note = "the file also holds a private key, which was not shown";
    d.problems = certProblems(d);
    return { ...out, ...d };
  }

  /** Which proxy variables are set and whether a URL would go through one. Credentials in a proxy URL are never shown. */
  function proxy(url) {
    const set = {};
    for (const k of ["HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "NO_PROXY"]) {
      const v = envOf(k);
      if (v) set[k] = k === "NO_PROXY" ? clip(v, 300) : redactUrl(v.includes("://") ? v : `http://${v}`).replace(/\/\/[^/@]*@/, `//${R}@`);
    }
    const out = { set };
    if (url) {
      let u;
      try {
        u = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(String(url)) ? String(url) : `https://${url}`);
      } catch {
        throw new Error("net.proxy: give a URL such as https://example.com, or nothing");
      }
      const p = proxyFor(u);
      out.url = redactUrl(u.href);
      out.used = p.used;
      if (p.used) Object.assign(out, { proxy: p.proxy, proxyHost: p.hostname, proxyPort: p.port, how: p.tunnel ? "CONNECT tunnel" : "plain forwarding" });
      out.via = p.via;
    } else if (!Object.keys(set).length) out.note = "no proxy variables are set; requests go direct";
    return out;
  }

  return { resolve, connect, request, cert, proxy };
}
