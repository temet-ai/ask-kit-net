export const meta = {
  purpose:
    "What a URL returns: the status, every redirect hop with its Location, the final headers (cookies and credentials redacted), timing split into DNS, connect, TLS and first byte, the TLS summary, and the first part of the body. GET only unless the caller asked for a change. The answer to 'what does this URL return', 'does it redirect', 'is it up', 'how slow is it'.",
  params: {
    url: "an http or https URL",
    method: "GET (default), HEAD or OPTIONS; another method only when the caller asked for a change",
    follow: "false to stop at the first response, default true",
    max: "body characters kept, default 1500, at most 16384; 0 for none",
    timeoutMs: "default 10000, at most 60000",
    insecure: "true to send the request although the certificate was not accepted",
    headers: "extra request headers as an object",
  },
  returns: "{verdict, url, ok, status, redirects, finalUrl, totalMs, hops:[{url, status, location?, via, timing, tls?, error?}], headers (final), body?:{type, bytes, text?, truncated?}, error?:{step, code, meaning}}",
  example: 'await scripts.run("url", { url: "https://example.com/health" })',
};

export default async function ({ net }, { url, method, follow, max = 1500, timeoutMs, insecure, headers } = {}) {
  if (!url) throw new Error("url needs `url`");
  const r = await net.request(url, { method, follow: follow === false || follow === "false" ? false : undefined, max: Number(max), timeoutMs, insecure: insecure === true || insecure === "true", headers });
  const last = r.hops.at(-1);
  const hops = r.hops.map((h) => ({ url: h.url, ...(h.status ? { status: h.status } : {}), ...(h.headers?.location ? { location: h.headers.location } : {}), via: h.via, timing: h.timing, ...(h.tls ? { tls: h.tls } : {}), ...(h.address ? { address: h.address } : {}), ...(h.note ? { note: h.note } : {}), ...(h.error ? { error: h.error } : {}) }));
  const err = r.error;
  const verdict = err
    ? `${r.url} could not be read: it failed at ${err.step} (${err.code}): ${err.meaning}`
    : `${r.method} ${r.url} gave ${r.status}${r.redirects ? ` after ${r.redirects} redirect${r.redirects > 1 ? "s" : ""} to ${r.finalUrl}` : ""} in ${r.totalMs} ms${last.note ? `; ${last.note}` : ""}${r.status >= 400 ? " (an error status)" : ""}`;
  return { verdict, url: r.url, ok: r.ok, status: r.status, redirects: r.redirects, finalUrl: r.finalUrl, totalMs: r.totalMs, hops, ...(last.headers ? { headers: last.headers } : {}), ...(r.body ? { body: r.body } : {}), ...(err ? { error: err } : {}), ...(r.note ? { note: r.note } : {}) };
}
