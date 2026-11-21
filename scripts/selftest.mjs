import http from "node:http";

export const meta = {
  purpose:
    "Starts a throwaway HTTP server on a free loopback port, requests four routes from it (200, a redirect, 404, a route that never answers) and stops it. Shows what each answer looks like and proves that this machine can make requests at all, separately from the network outside. Nothing else is touched.",
  params: {},
  returns: "{verdict, port, ok:{status}, redirect:{status, redirects, finalUrl}, missing:{status, ok}, hang:{error}, stopped}",
  example: 'await scripts.run("selftest")',
};

export default async function ({ net }) {
  const server = http.createServer((req, res) => {
    if (req.url === "/ok") {
      res.setHeader("set-cookie", "sid=hunter2; HttpOnly");
      res.setHeader("content-type", "text/plain");
      res.end("hello from the selftest");
    } else if (req.url === "/moved") {
      res.writeHead(301, { location: "/ok" });
      res.end();
    } else if (req.url === "/hang") {
      // never answers: the client's time limit ends it
    } else {
      res.writeHead(404, { "content-type": "text/plain" });
      res.end("no such route");
    }
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const port = server.address().port;
  const base = `http://127.0.0.1:${port}`;
  try {
    const ok = await net.request(`${base}/ok`);
    const moved = await net.request(`${base}/moved`);
    const missing = await net.request(`${base}/nothing`);
    const hang = await net.request(`${base}/hang`, { timeoutMs: 400 });
    return {
      verdict: `loopback requests work: /ok ${ok.status}, /moved ${moved.status} after ${moved.redirects} redirect, /nothing ${missing.status}, /hang ${hang.error ? `timed out (${hang.error.code})` : hang.status}`,
      port,
      ok: { status: ok.status, cookie: ok.hops[0].headers["set-cookie"], body: ok.body?.text },
      redirect: { status: moved.status, redirects: moved.redirects, finalUrl: moved.finalUrl },
      missing: { status: missing.status, ok: missing.ok },
      hang: { error: hang.error },
      stopped: true,
    };
  } finally {
    server.closeAllConnections?.();
    await new Promise((r) => server.close(r));
  }
}
