export const meta = {
  purpose:
    "The TLS certificate a server presents, or one in a PEM file: who it was issued to and by, the names it covers, when it expires and how many days are left, whether it is self-signed, whether the chain verifies and why not. The answer to 'when does the certificate for example.com expire', 'who issued it', 'is the cert valid', 'does it cover this name'.",
  params: { host: "host name, \"host:port\" or an https URL; port defaults to 443", port: "the port", file: "a .pem, .crt or .der file instead of a host", name: "a name the certificate must cover, when it is not the host", now: "judge expiry at this date (2026-06-01) instead of today", timeoutMs: "default 8000" },
  returns: "{verdict, source, subject, issuer, sans, validFrom, validTo, daysLeft, expired, selfSigned, chainVerifies, chainNote?, chain?, problems, coversName?, protocol?, cipher?, error?}",
  example: 'await scripts.run("cert", { host: "example.com" })',
};

export default async function ({ net }, { host, port, file, name, now, timeoutMs } = {}) {
  if (!host && !file) throw new Error("cert needs `host` or `file`");
  const r = file ? await net.cert({ file, name, now }) : await net.cert(host, port, { servername: name, now, timeoutMs });
  if (r.error) return { verdict: `no certificate read from ${r.source}: ${r.error.step} ${r.error.code}: ${r.error.meaning}`, ...r };
  const issuer = r.issuer.match(/CN=([^,]+)/)?.[1] ?? r.issuer;
  const state = r.expired ? `expired ${-r.daysLeft} days ago` : r.notYetValid ? "not valid yet" : `expires ${r.validTo.slice(0, 10)}, in ${r.daysLeft} days`;
  const verdict = `${r.source}: certificate for ${r.commonName ?? r.subject} issued by ${issuer}, ${state}${r.problems.length ? `; problems: ${r.problems.join("; ")}` : "; nothing wrong with it"}${r.intercepted ? "; this is a proxy's certificate, not the site's" : ""}`;
  return { verdict, ...r };
}
