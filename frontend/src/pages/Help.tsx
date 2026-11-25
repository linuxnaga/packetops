import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { get } from "../api/client";
import { ErrorBox, PageHeader, Section, SeverityBadge, Spinner } from "../components/ui";

interface Rule { rule_id: string; version: string; title: string; category: string; default_severity: string; required_evidence: string[]; detection_logic: string;
  limitations: string[]; false_positives: string[]; severity_rationale: string }

const FILTER_HELP: [string, string][] = [
  ["ip.addr == 10.0.0.1", "either address"],
  ["tcp.port == 443 && tcp.flags.reset == 1", "resets on port 443"],
  ["flow == \"t3\"", "all packets of conversation t3"],
  ["frame.number >= 100 && frame.number <= 200", "a frame range"],
  ["dns.qry.name contains \"api\"", "DNS queries by name"],
  ["tcp.analysis.retransmission", "retransmitted segments"],
  ["http.host contains \"example\"", "HTTP requests by Host header"],
  ["!(udp.port == 53)", "negation"],
];

export default function Help() {
  const [q, setQ] = useState("");
  const { data, isLoading, error } = useQuery({ queryKey: ["rules"], queryFn: () => get<Rule[]>("/rules") });
  const rules = (data ?? []).filter((r) => !q || `${r.rule_id} ${r.title} ${r.category}`.toLowerCase().includes(q.toLowerCase()));
  return (
    <div className="space-y-4">
      <PageHeader title="Rules & help" subtitle="Every finding comes from one of these versioned rules. Each rule lists the evidence it needs, how it decides, and where it can be wrong." />
      <div className="grid gap-4 lg:grid-cols-2">
        <Section title="Display filter language">
          <p className="mb-2 text-sm text-muted">A safe subset of Wireshark display-filter syntax: comparisons (==, !=, &lt;, &lt;=, &gt;, &gt;=), contains, &&, ||, ! and parentheses over the indexed fields.</p>
          <table className="tbl"><tbody>{FILTER_HELP.map(([f, d]) => <tr key={f}><td className="mono">{f}</td><td className="text-muted">{d}</td></tr>)}</tbody></table>
        </Section>
        <Section title="How to read a finding">
          <ul className="list-disc space-y-1 pl-5 text-sm">
            <li><b>Observed facts</b> are measured from packets and link to the frames.</li>
            <li><b>Interpretation</b> and <b>probable cause</b> are the rule's reasoning; <b>alternatives</b> list other explanations that fit the same packets.</li>
            <li><b>Confidence</b> reflects how directly the packets prove the conclusion, not how severe it is.</li>
            <li><b>Missing evidence</b> says what would confirm or rule out the cause, such as a capture from the other side.</li>
            <li>Verification commands are suggestions to run yourself. PacketOps never runs commands on your devices.</li>
            <li>The AI copilot only summarises these findings. Its output is checked against the evidence and replaced by a deterministic summary when it fails that check.</li>
          </ul>
        </Section>
      </div>
      <Section title={`Detection rules (${data?.length ?? 0})`} actions={<input className="input max-w-[14rem] py-1" value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search rules" aria-label="Search rules" />}>
        {isLoading ? <Spinner /> : error ? <ErrorBox error={error} /> : (
          <div className="space-y-2">
            {rules.map((r) => (
              <details key={r.rule_id} className="rounded-md border border-line p-3">
                <summary className="cursor-pointer"><span className="mono font-semibold">{r.rule_id}</span> <span className="text-xs text-muted">v{r.version}</span> · {r.title} <SeverityBadge severity={r.default_severity} /></summary>
                <div className="mt-2 grid gap-3 text-sm md:grid-cols-2">
                  <div><div className="label">Detection logic</div><p>{r.detection_logic}</p></div>
                  <div><div className="label">Severity rationale</div><p>{r.severity_rationale}</p></div>
                  <div><div className="label">Required evidence</div><ul className="list-disc pl-5">{r.required_evidence.map((x) => <li key={x}>{x}</li>)}</ul></div>
                  <div><div className="label">Limitations</div><ul className="list-disc pl-5">{r.limitations.map((x) => <li key={x}>{x}</li>)}</ul></div>
                  <div><div className="label">Known false positives</div><ul className="list-disc pl-5">{r.false_positives.map((x) => <li key={x}>{x}</li>)}</ul></div>
                </div>
              </details>
            ))}
          </div>
        )}
      </Section>
    </div>
  );
}
