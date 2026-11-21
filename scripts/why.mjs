export const meta = {
  purpose:
    "Why a URL or host cannot be reached: checks, in order, the proxy settings, the name, the TCP connection, the TLS certificate and the HTTP answer, and names the first step that fails with what it usually means. Only the host named is touched. The answer to 'why can't I reach X', 'why does this URL fail', 'connection refused', 'ETIMEDOUT', 'ENOTFOUND', 'certificate error'.",
  params: { target: "a URL, or host or host:port (a bare host is tried as https://host)", timeoutMs: "per step, default 6000" },
  returns: "{verdict, target, failedAt?, steps:[{step, ok, detail}], error?, proxy, hint?}",
  example: 'await scripts.run("why", { target: "https://example.com" })',
};

export default async function ({ net }, { target, timeoutMs = 6000 } = {}) {
  if (!target) throw new Error("why needs `target`");
  const t = String(target).trim();
  const hasScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(t);
  const hp = !hasScheme && t.match(/^\[?([^\]/]+?)\]?:(\d+)$/);
  const url = hasScheme ? t : hp ? `${hp[2] === "443" ? "https" : "http"}://${t}` : `https://${t}`;
  const u = new URL(url);
  const port = Number(u.port) || (u.protocol === "https:" ? 443 : 80);
  const steps = [];
  const proxy = net.proxy(url);
  steps.push({ step: "proxy", ok: true, detail: proxy.via });
  const dns = await net.resolve(u.hostname, { timeoutMs });
  const addrs = dns.kind === "address" ? [u.hostname.replace(/^\[|\]$/g, "")] : (dns.system?.addresses ?? []);
  // Through a proxy the proxy resolves the name, so this machine's answer is information, not the fault.
  steps.push({ step: "dns", ok: proxy.used || addrs.length > 0, detail: dns.kind === "address" ? `${u.hostname} is an address, no name to resolve` : proxy.used && !addrs.length ? `this machine cannot resolve ${u.hostname} (${dns.system?.meaning ?? dns.note}); the proxy resolves it instead` : addrs.length ? `${u.hostname} resolves to ${addrs.slice(0, 4).join(", ")}${dns.differ ? `; ${dns.note}` : ""}` : `${u.hostname} does not resolve: ${dns.system?.meaning ?? dns.note}` });
  const direct = !proxy.used;
  if (direct && addrs.length) {
    const c = await net.connect(u.hostname, port, { timeoutMs });
    steps.push({ step: "tcp", ok: c.open, detail: c.open ? `port ${port} answers on ${c.attempts.filter((a) => a.open).map((a) => a.address).join(", ")}` : `port ${port} does not answer: ${c.attempts[0]?.meaning}` });
  }
  const r = await net.request(url, { timeoutMs: Math.max(1000, timeoutMs), follow: true, max: 0 });
  const e = r.error;
  const hasTls = r.hops.some((h) => h.tls);
  if (u.protocol === "https:" && (hasTls || e?.step === "tls")) {
    const tls = r.hops.find((h) => h.tls)?.tls;
    steps.push({ step: "tls", ok: !e || e.step !== "tls", detail: tls ? `${tls.subject} issued by ${tls.issuer}, ${tls.daysLeft} days left${tls.problems.length ? `; ${tls.problems.join("; ")}` : ""}` : e.meaning });
  }
  if (!(e && steps.at(-1).step === "tls" && !steps.at(-1).ok)) steps.push({ step: "http", ok: !e && r.status < 400, detail: e ? `${e.step} ${e.code}: ${e.meaning}` : `${r.status}${r.redirects ? ` after ${r.redirects} redirects, ending at ${r.finalUrl}` : ""} in ${r.totalMs} ms` });
  const failed = steps.find((s) => !s.ok);
  const out = { target: url, failedAt: failed?.step ?? null, steps, proxy: proxy.via };
  if (e) out.error = e;
  let verdict;
  if (failed) verdict = `${url} fails at ${failed.step}: ${failed.detail}${proxy.used && !addrs.length ? `; this machine's DNS cannot resolve the name either, so the name may not exist` : ""}`;
  else verdict = `${url} is reachable from this machine (${steps.at(-1).detail})`;
  if (failed?.step === "http" && !e) verdict = `${url} is reachable, but the server answers ${r.status}`;
  if (u.hostname === "localhost" || /^127\./.test(u.hostname) || u.hostname === "::1" || u.hostname === "[::1]") out.hint = "for a local port, which process holds it (or whether anything does) is the procs kit";
  return { verdict, ...out };
}
