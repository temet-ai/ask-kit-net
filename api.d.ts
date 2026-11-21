interface Failure {
  step: "dns" | "tcp" | "tls" | "proxy" | "http" | "file" | "refused";   // where it went wrong
  code: string;       // ECONNREFUSED, ETIMEDOUT, ENOTFOUND, CERT_HAS_EXPIRED, ...
  meaning: string;    // what that code usually means, in plain words
  hint?: string;
}

interface CertInfo {
  source: string;                 // "host:port" or the file's full path
  subject: string; commonName: string | null; sans: string[];   // sans: the names it covers
  issuer: string;
  validFrom: string; validTo: string;     // ISO dates
  daysLeft: number;                       // negative once expired
  expired: boolean; notYetValid: boolean; selfSigned: boolean;
  key: string; fingerprint256: string;
  nameAsked?: string; coversName?: boolean;
  chainVerifies: boolean | null;          // null: could not be checked (issuer unknown)
  chainNote?: string; verifyError?: string;
  privateCA?: string;                     // the chain ends at a CA this machine trusts and public browsers do not
  intercepted?: boolean;                  // the request went through a proxy that re-signs TLS: this is the proxy's certificate
  chain?: { subject: string; issuer: string; validTo: string; daysLeft: number }[];
  problems: string[];                     // what a person would act on, worst first; empty means nothing is wrong
  protocol?: string; cipher?: string;     // when read from a server
  via?: string; address?: string; servername?: string;
  error?: Failure;                        // instead of the rest, when nothing could be read
}

declare const net: {
  // What a name resolves to. `system` is what programs on this machine get (hosts file, then DNS); `dns` is what the
  // DNS servers say per record type; `differ` says whether they disagree, with `note` saying why when they do.
  // An IP address as the name gives its reverse names in `ptr`. types default ["A","AAAA","CNAME"]; also MX, TXT, NS,
  // SOA or "all". server: ask this DNS server (an IP) instead of the system's. Never longer than timeoutMs (default 5000).
  resolve(name: string, o?: { types?: string | string[]; server?: string; timeoutMs?: number }): Promise<{
    name: string; servers: string[]; kind?: "address";
    system?: { addresses: string[]; error?: string; meaning?: string };
    dns?: { records: Record<string, any[]>; errors?: Record<string, string>; meaning?: string; unreachable?: boolean };
    hostsFile?: string[]; differ?: boolean | null; note?: string; ptr?: string[]; error?: { code: string; meaning: string };
  }>;

  // Whether a host and port answer: one TCP connection per address the host resolves to (at most 6), in parallel,
  // each with its milliseconds or its error code and meaning. Touches only the host and port given.
  // host may be "host:port" when port is left out. timeoutMs default 3000 per address, at most 20000.
  connect(host: string, port?: number, o?: { timeoutMs?: number }): Promise<{
    host: string; port: number; via: "direct"; resolved: string[]; open: boolean;
    attempts: { address: string; family: number; open: boolean; ms: number; code?: string; meaning?: string }[];
    error?: Failure; proxyNote?: string; moreAddresses?: number;
  }>;

  // What a URL returns (http or https). Follows up to `redirects` (default 5, at most 10) for GET, HEAD and OPTIONS and
  // returns every hop. Any other method (POST, PUT, PATCH, DELETE) throws "not in this ask" unless the caller asked for a
  // change. Honours HTTP_PROXY, HTTPS_PROXY and NO_PROXY and says in `via` which way each hop went. Cookies, Authorization,
  // secret-looking headers, URL passwords and secret-looking query values are replaced with <redacted>. Cloud metadata
  // addresses are refused. A certificate that is expired, not trusted or for another name stops the request with
  // error.step "tls" unless insecure is true. max: body characters kept (default 2048, at most 16384; 0 for none).
  // timeoutMs: for each hop, default 10000, at most 60000. The body is cut and `truncated` says so.
  request(url: string, o?: { method?: string; headers?: Record<string, string>; body?: string | object; follow?: boolean; redirects?: number; max?: number; timeoutMs?: number; insecure?: boolean; allHeaders?: boolean }): Promise<{
    url: string; method: string; ok: boolean; status: number | null; redirects: number; finalUrl: string; totalMs: number;
    hops: { url: string; status?: number; via: string; address?: string; timing: { dns: number | null; connect: number | null; tls: number | null; firstByte: number | null; total: number | null }; headers?: Record<string, any>; headersNotShown?: number; tls?: { protocol: string; subject: string; issuer: string; validTo: string; daysLeft: number; coversName: boolean; chainVerifies: boolean; problems: string[]; note?: string; intercepted?: boolean }; note?: string; failedAddresses?: { address: string; code: string }[] }[];
    body?: { type: string | null; bytes: number | null; bytesRead?: number; text?: string; truncated?: string; binary?: boolean; encoding?: string; note?: string };
    error?: Failure; note?: string; sentHeaderNames?: string[];
  }>;

  // The TLS certificate a server presents, or one in a PEM or DER file ({file}, relative to the working folder). Reads only
  // a port that speaks TLS from the first byte (not STARTTLS ports such as 25 or 587). servername: the name to ask for
  // when it is not the host. now: judge expiry at this date ("2026-06-01") instead of today.
  cert(host: string, port?: number, o?: { servername?: string; now?: string | number; timeoutMs?: number }): Promise<CertInfo>;
  cert(o: { file: string; name?: string; now?: string | number } | { host: string; port?: number; servername?: string; now?: string | number; timeoutMs?: number }): Promise<CertInfo>;

  // Which proxy variables are set (credentials never shown) and whether a URL would go through one.
  proxy(url?: string): { set: Record<string, string>; url?: string; used?: boolean; proxy?: string; how?: string; via?: string; note?: string };
};
