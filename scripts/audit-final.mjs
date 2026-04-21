import { readFileSync } from "node:fs";

const path = process.argv[2] || "datasets/pentesterflow_v2_dataset_2026-04-21T02-21-05_filtered.jsonl";
const lines = readFileSync(path, "utf8").split("\n").filter(Boolean);

let triage = 0, withReport = 0, withCode = 0;
const turnsTriage = [], turnsFull = [];
const toolCalls = {};
let totalCalls = 0;

for (const l of lines) {
  const o = JSON.parse(l);
  if (o.metadata.is_triage) triage++;
  let hasCvss = false, hasCode = false;
  for (const m of o.conversations) {
    if (m.from === "gpt") {
      if (m.value?.includes("CVSS") || m.value?.includes("Remediation")) hasCvss = true;
      if (m.value?.includes("```")) hasCode = true;
    }
    if (m.tool_calls) {
      for (const tc of m.tool_calls) {
        toolCalls[tc.name] = (toolCalls[tc.name] || 0) + 1;
        totalCalls++;
      }
    }
  }
  if (hasCvss) withReport++;
  if (hasCode) withCode++;
  if (o.metadata.is_triage) turnsTriage.push(o.metadata.turn_count);
  else turnsFull.push(o.metadata.turn_count);
}

const avg = arr => arr.length ? (arr.reduce((a, b) => a + b, 0) / arr.length).toFixed(1) : "n/a";

console.log(`file: ${path}`);
console.log(`total entries: ${lines.length}`);
console.log(`triage entries: ${triage} (${(triage / lines.length * 100).toFixed(1)}%)`);
console.log(`entries with CVSS/Remediation: ${withReport} (${(withReport / lines.length * 100).toFixed(1)}%)`);
console.log(`entries with any code fence: ${withCode} (${(withCode / lines.length * 100).toFixed(1)}%)`);
console.log(`avg turns — triage: ${avg(turnsTriage)} | full: ${avg(turnsFull)}`);
console.log(`\ntop tools by calls (of ${totalCalls} total):`);
for (const [n, c] of Object.entries(toolCalls).sort((a, b) => b[1] - a[1]).slice(0, 12)) {
  console.log(`  ${n.padEnd(18)} ${c.toString().padStart(6)} (${(c / totalCalls * 100).toFixed(1)}%)`);
}
