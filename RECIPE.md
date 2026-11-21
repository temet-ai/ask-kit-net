# Recipe: the net kit

## What it answers

What a name resolves to, whether a host and port answer, what a URL returns (status, redirects,
headers, timing), when a TLS certificate expires and who issued it, and why something cannot be
reached. It also acts: sends an HTTP request that changes something, when asked.

## What it needs

- ask-kit 0.3 or later (`min_ask_kit = "0.3.0"`) and Node (run on Node 26). No settings are required, no tokens.
- Network access to whatever a question names. With none, the checks that use the internet fail
  and the ones that use loopback and the fixture files still pass.

## What it reads and runs

Node built-ins only (`node:dns`, `node:net`, `node:tls`, `node:http`, `node:crypto`); it runs no
other program. It reads `/etc/hosts` to say whether a hosts-file entry is why a name resolves
as it does, the proxy environment variables, Node's CA store to judge a chain, and a
certificate file when one is named. It opens connections only to the host and port a question
names and to the targets of redirects. It never reads cookies, browser profiles or credentials
files.

## Brief to rebuild it from an empty folder

Make a folder with `ask-kit.toml` (id `temet.net`, name `net`, `says`, `keywords`, `route_hint`
that sends local listening ports to procs, `cite`, one `WORKDIR` setting, one `module` source
named `net` with `net.mjs` and `api.d.ts`, `acts` as prose naming every method except GET, HEAD
and OPTIONS because a phrase such as `net.request` would also block reading calls, and two
`[[actions]]`, `cert` and `resolve`) and `instructions = "instructions.md"`.

`net.mjs` exports `make({settings, push, act})` returning `{resolve, connect, request, cert,
proxy}`:

- `resolve(name, {types, server})`: `dns.lookup` for the system answer, a `dns.Resolver` for
  record types, `/etc/hosts` lines, `differ` when they disagree; `reverse` for an address.
- `connect(host, port)`: `dns.lookup`, then one TCP connection per address (at most 6) in
  parallel, each with a timeout.
- `request(url, o)`: one socket per hop, built by hand (proxy `CONNECT` when the proxy variables
  say so, TLS with `rejectUnauthorized: false` and the chain checked afterwards, so a bad
  certificate can be described), `http.request` over that socket with no agent, timing per step,
  redirects followed for GET, HEAD and OPTIONS only, any other method throws "not in this ask"
  unless `act`. Headers go through a redaction pass; a body is read up to a cap and cut.
- `cert(host, port)` and `cert({file})`: the peer chain from the socket or the PEM blocks from the
  file, `X509Certificate` for subject, names, issuer, dates, key, and a chain check against
  Node's root store; `now` judges expiry at a given date.
- `proxy(url)`: which proxy variables are set and whether a URL would use one.
- Cloud metadata addresses are refused in every call, including after a redirect and for a name
  that resolves to one.

Scripts in `scripts/` (each `export const meta = {purpose, params, returns, example}` and
`export default async function ({net}, params)`), each returning a `verdict` first: `resolve`,
`reach`, `url`, `cert`, `why` (proxy, name, TCP, TLS, HTTP in order, first failure named) and
`selftest` (a throwaway loopback server with four routes, stopped before it returns).

`instructions.md` says: start from a script; touch only what was named; name the failing step;
read `via` for the proxy; report issuer, expiry and every problem; one request is one sample;
reading only unless `act`; say that a local port's holder is for procs.

## Bench

Six model questions and six shots. The model questions use example.com and github.com, localhost
port 1, and two certificate files made for the bench (`bench/fixture`, asked about at the fixed
date 2026-06-01). The shots call no model. Run the bench from the kit's folder.

## Results

All twelve entries were checked by running the scripts and matching each `expect` pattern against
their output on 2026-11-21 (Linux). The model questions have not been run on a model.
