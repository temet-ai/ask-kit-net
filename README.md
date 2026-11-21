# ask-kit-net

An [ask-kit](https://github.com/temet-ai/ask-kit) kit that lets your coding agent's `ask` tool
answer questions about the network as seen from your machine. A cheap model makes the lookups
and requests outside your agent's context and answers with the step that worked or failed (name,
connection, TLS, HTTP), the status or error code, and the numbers. It uses Node's own DNS, TCP,
TLS and HTTP code, so it needs no `dig`, `curl` or `openssl`.

Questions it is for:

- When does the certificate for example.com expire, and who issued it? (answered by a script, with no model)
- What does https://example.com/health return: status, redirects, headers, how long each step took?
- Why can't I reach staging.example.com: does it resolve, does the port answer, is the certificate rejected, is a proxy in the way?
- Is db.internal:5432 reachable from here?

## Install

You need [ask-kit](https://github.com/temet-ai/ask-kit#set-it-up) 0.3 or later and Node (run on Node 26).
Nothing else.

Paste this into your agent:

```
Read ~/.config/ask-kit/AGENTS.md, then add this kit: github.com/temet-ai/ask-kit-net
```

Or run it yourself:

```sh
ask-kit kit install temet-ai/ask-kit-net        # shows what it reads, changes and runs
ask-kit kit install temet-ai/ask-kit-net --yes  # installs and enables it
```

Restart your agents so `ask` lists `net`. The kit has one optional setting, `WORKDIR`, the
folder that relative certificate file paths start from (by default the folder the agent runs in).

## What it carries

`net.mjs` is the source the model's REPL gets: `net.resolve`, `net.connect`, `net.request`,
`net.cert` and `net.proxy`. Its scripts each answer one question with a one-line `verdict` first:

- `resolve`: what a name resolves to, what the system resolver and the DNS servers each say, and
  whether they differ; MX, TXT, NS and SOA records; the reverse name of an address.
- `reach`: whether a named host and port answer, with the time for each address or the error.
- `url`: what a URL returns: status, each redirect hop, headers, timing (DNS, connect, TLS, first
  byte), the TLS summary and the start of the body.
- `cert`: the certificate a server presents, or one in a PEM file: subject, names covered,
  issuer, expiry and days left, self-signed or not, whether the chain verifies and why not.
- `why`: walks proxy, name, TCP, TLS and HTTP for a URL or host and names the first step that fails.
- `selftest`: starts a throwaway server on loopback, requests four routes from it and stops it,
  which shows that this machine can make requests at all.

It follows the proxy variables (`HTTPS_PROXY`, `HTTP_PROXY`, `ALL_PROXY`, `NO_PROXY`) the way
other tools do and says in every result whether a request went direct or through a proxy,
because through a proxy the proxy resolves the name and makes the connection.

It touches only the hosts and ports a question names, plus where a redirect leads. It does not
scan. Every lookup, connection and request has a time limit (a few seconds by default, 60 at
most) and bodies and lists are cut with a note saying how much. It has no skills or roles: each
job is one script.

Which process holds a local port is the [procs](https://github.com/temet-ai/ask-kit-procs) kit.

## What it can change

Reading is all it does unless the ask was made with `act: true`. Then it can send an HTTP
request with another method than GET, HEAD or OPTIONS (POST, PUT, PATCH, DELETE), with the body
and headers you name. Without `act`, `net.request` throws "not in this ask" for those methods
before anything is sent.

Output goes to a cloud model, so before it leaves the kit:

- cookies, `Authorization` and secret-looking headers, URL passwords, secret-looking query values
  and secret-looking `key=value` pairs in a body are shown as `<redacted>`. The redaction is by
  pattern: a secret in an unusual shape can get through;
- cloud metadata addresses (169.254.169.254, `metadata.google.internal` and the like) are
  refused, whether named directly or reached by a redirect or a DNS answer;
- a private key found in a certificate file is never shown.

## How well it works

`bench/questions.json` holds six questions for a model and six checks that run with no model.
The six checks (a name that does not resolve, a refused port, why localhost:1 fails, an expired
self-signed certificate and a private-CA chain read from files in `bench/fixture`, and the
loopback `selftest`) and the patterns of the six model questions were run against the kit's
output on 2026-11-21 and matched. The model questions have not been run on a model. The
reading and holding-back rules were checked against a local server: GET, HEAD and OPTIONS run,
POST, PUT, PATCH and DELETE are held without `act` and the server saw none of them. The proxy path
was run through the proxy this machine uses; a proxy with credentials and plain forwarding
through a proxy are written and not run.

MIT licence. [RECIPE.md](RECIPE.md) says what it reads and runs, and how to rebuild it.
