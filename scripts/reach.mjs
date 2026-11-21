export const meta = {
  purpose:
    "Whether a host and port answer: a TCP connection to every address the host resolves to, with the milliseconds it took, or the error and what it means (refused, timed out, no route, no such name). Only the host and port named are touched. The answer to 'is db.example.com:5432 reachable', 'does it answer on 443', 'is the port open from here'.",
  params: { host: "host name or IP, or \"host:port\"", port: "the port, 1 to 65535", timeoutMs: "per address, default 3000, at most 20000" },
  returns: "{verdict, host, port, open, resolved, attempts:[{address, family, open, ms, code?, meaning?}], error?, proxyNote?}",
  example: 'await scripts.run("reach", { host: "example.com", port: 443 })',
};

export default async function ({ net }, { host, port, timeoutMs } = {}) {
  if (!host) throw new Error("reach needs `host` (and `port`)");
  const r = await net.connect(host, port, { timeoutMs });
  const ok = r.attempts.filter((a) => a.open);
  const bad = r.attempts.filter((a) => !a.open);
  let verdict;
  if (r.error) verdict = `${r.host} does not resolve: ${r.error.meaning}`;
  else if (ok.length) verdict = `${r.host}:${r.port} answers (${ok.length} of ${r.attempts.length} addresses, ${Math.min(...ok.map((a) => a.ms))} ms to the fastest)${bad.length ? `; ${bad.map((a) => `${a.address} ${a.code}`).join(", ")}` : ""}`;
  else verdict = `${r.host}:${r.port} does not answer: ${bad[0].meaning}`;
  const local = r.resolved.length && r.resolved.every((a) => a === "127.0.0.1" || a === "::1");
  return { verdict, ...r, ...(local && !r.open ? { hint: "this is a local address: which process holds a local port is the procs kit" } : {}) };
}
