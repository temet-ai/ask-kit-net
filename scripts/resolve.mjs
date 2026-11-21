export const meta = {
  purpose:
    "What a name resolves to: the addresses programs on this machine get (hosts file, then DNS) and what the DNS servers say per record type, and whether the two differ. For an IP address, its reverse (PTR) names. The answer to 'does example.com resolve', 'what IP is it', 'what are its MX or TXT records', 'why does this name resolve here and not there'.",
  params: { name: "a host name, a URL, or an IP address", types: "record types, default A, AAAA, CNAME; also MX, TXT, NS, SOA, or \"all\"", server: "ask this DNS server instead of the system's, an IP such as 1.1.1.1" },
  returns: "{verdict, name, kind?, system?:{addresses}, dns?:{records}, differ, hostsFile?, note?, servers, ptr?}",
  example: 'await scripts.run("resolve", { name: "example.com", types: "A,MX" })',
};

export default async function ({ net }, { name, types, server } = {}) {
  if (!name) throw new Error("resolve needs `name`");
  const r = await net.resolve(name, { types, server });
  let verdict;
  if (r.kind === "address") verdict = r.note;
  else {
    const sys = r.system?.addresses ?? [];
    const recs = Object.entries(r.dns?.records ?? {}).filter(([, v]) => Array.isArray(v) && v.length);
    if (r.dns?.unreachable) verdict = `${r.name}: the DNS servers did not answer from this machine; ${sys.length ? `the system resolver gives ${sys.join(", ")}` : "the system resolver fails too"}`;
    else if (!sys.length && !recs.length) verdict = `${r.name} does not resolve: ${r.system?.meaning ?? "no records"}`;
    else verdict = `${r.name} resolves to ${sys.length ? sys.slice(0, 6).join(", ") : "nothing on this machine"}${sys.length > 6 ? ` (and ${sys.length - 6} more)` : ""}${recs.length ? `; DNS records: ${recs.map(([t, v]) => `${t} ${v.length}`).join(", ")}` : ""}${r.differ ? `; ${r.note}` : ""}`;
  }
  return { verdict, ...r };
}
