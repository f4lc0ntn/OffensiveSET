import { readFileSync, writeFileSync, createWriteStream, mkdirSync } from "node:fs";
import { resolve, basename, dirname } from "node:path";
import { scoreEntryQuality } from "../dist/generators/v2/quality.js";

const inputPath = resolve(process.argv[2] || "./datasets/pentesterflow_v2_dataset_2026-04-20T22-34-26.jsonl");
const minQuality = Number(process.env.MIN_QUALITY || 0.6);
const maxCurlShare = Number(process.env.MAX_CURL_SHARE || 0.75);
const outDir = dirname(inputPath);

const baseName = basename(inputPath, ".jsonl");
const filteredPath = resolve(outDir, `${baseName}_filtered.jsonl`);
const qwenPath = resolve(outDir, `${baseName}_chatml_qwen.jsonl`);
const sharegptPath = resolve(outDir, `${baseName}_sharegpt.jsonl`);
const statsPath = resolve(outDir, `${baseName}_filtered_stats.json`);

console.error(`[filter] input=${inputPath}`);
console.error(`[filter] minQuality=${minQuality} maxCurlShare=${maxCurlShare}`);

// Contradiction detection — hoisted above the main loop so hasContradiction()
// sees these constants when it runs during per-line iteration.
const HARD_FAILURE_RX = /Connection refused|Failed to connect|Could not resolve|No route to host|Host unreachable|Name or service not known|NXDOMAIN|operation timed out/i;
const SUCCESS_CLAIM_RX = /\b(vulnerab(le|ility)|successful(ly)?|exploit(ed|ation successful)|confirmed the (issue|vuln|exploit)|bypass (worked|successful)|access granted|shell obtained|extracted \d+ (records|rows)|dumped the database|RCE achieved|executed arbitrary)\b/i;

function hasContradiction(entry) {
  const msgs = entry.conversations;
  for (let i = 0; i < msgs.length - 1; i++) {
    const obs = msgs[i];
    if (obs.from !== "tool" && obs.from !== "observation") continue;
    const obsText = (obs.value || "") + (obs.tool_results?.map(r => r.output).join("\n") || "");
    if (!HARD_FAILURE_RX.test(obsText)) continue;
    for (let j = i + 1; j < msgs.length; j++) {
      if (msgs[j].from !== "gpt") continue;
      if (SUCCESS_CLAIM_RX.test(msgs[j].value || "")) return true;
      break;
    }
  }
  return false;
}

const KNOWN_TOOLS_RX = /\b(nmap|sqlmap|ffuf|nuclei|httpx|curl|nikto|wfuzz|dalfox|gobuster|arjun|subfinder|amass|jwt_tool|hydra|metasploit|katana|rustscan|linpeas|nosqlmap|commix|ssrfmap|crlfuzz|corsy|paramspider|aws_cli|semgrep|trufflehog|testssl|kubectl|report_generator|python_script|bash|feroxbuster|dirsearch|dnsx|puredns|gau|gf|secretfinder|linkfinder|kiterunner|caido|interactsh)\b/gi;

// Causal attribution check: for each post-observation gpt turn, the tool
// names mentioned in narrative prose must be either (a) tools invoked in
// the immediately preceding tool_calls or (b) tools invoked somewhere
// earlier in the conversation AND introduced by explicit recap language.
// A mention that is neither is a hallucinated attribution — drop the entry.
function attributionError(entry) {
  const msgs = entry.conversations;
  const convTools = new Set();
  for (const m of msgs) if (m.tool_calls) for (const tc of m.tool_calls) if (tc.name) convTools.add(tc.name.toLowerCase());

  for (let i = 0; i < msgs.length - 1; i++) {
    const m = msgs[i];
    if (m.from !== "tool" && m.from !== "observation") continue;
    // find preceding tool_calls
    let actualTools = new Set();
    for (let k = i - 1; k >= 0; k--) {
      if (msgs[k].from === "gpt" && msgs[k].tool_calls?.length) {
        for (const tc of msgs[k].tool_calls) if (tc.name) actualTools.add(tc.name.toLowerCase());
        break;
      }
      if (msgs[k].from === "gpt") break;
    }
    const next = msgs.slice(i + 1).find(mm => mm.from === "gpt");
    if (!next || actualTools.size === 0) continue;

    const body = (next.value || "")
      .replace(/<think>[\s\S]*?<\/think>/g, "")
      .replace(/```[\s\S]*?```/g, "")
      .replace(/<tool_call>[\s\S]*?<\/tool_call>/g, "")
      .replace(/<tool_response>[\s\S]*?<\/tool_response>/g, "");
    const mentioned = new Set([...(body.match(KNOWN_TOOLS_RX) || [])].map(s => s.toLowerCase()));
    if (mentioned.size === 0) continue;

    const strictForeign = [...mentioned].filter(t => !actualTools.has(t));
    if (strictForeign.length === 0) continue;

    const isRecap = /(earlier|earlier result|earlier scan|consistent with what|what .* showed|prior|prior phase|previous run|from the first phase)/i.test(body);
    if (isRecap && strictForeign.every(t => convTools.has(t))) continue; // legitimate recap of earlier phases

    // Hallucinated attribution — not in preceding call, not a legitimate recap.
    return true;
  }
  return false;
}

const lines = readFileSync(inputPath, "utf8").split("\n").filter(Boolean);
console.error(`[filter] total input entries: ${lines.length}`);

const filteredOut = createWriteStream(filteredPath);
const qwenOut = createWriteStream(qwenPath);
const sharegptOut = createWriteStream(sharegptPath);

const stats = {
  input: lines.length,
  kept: 0,
  droppedLowQuality: 0,
  droppedCurlHeavy: 0,
  avgScoreIn: 0,
  avgScoreOut: 0,
  toolDist: {},
  categoryDist: {},
  difficultyDist: {},
};

let scoreSumIn = 0;
let scoreSumOut = 0;

for (const line of lines) {
  let entry = JSON.parse(line);
  const { overall } = scoreEntryQuality(entry);
  scoreSumIn += overall;
  entry = scrubPlaceholders(entry);

  if (overall < minQuality) {
    stats.droppedLowQuality++;
    continue;
  }

  let curlCalls = 0;
  let totalCalls = 0;
  for (const m of entry.conversations) {
    if (m.tool_calls) {
      for (const tc of m.tool_calls) {
        totalCalls++;
        if (tc.name === "curl") curlCalls++;
      }
    }
  }
  if (totalCalls === 0) {
    // Entries without any tool calls hurt tool-use fine-tuning; drop them.
    stats.droppedNoCalls = (stats.droppedNoCalls || 0) + 1;
    continue;
  }
  if (totalCalls > 0 && curlCalls / totalCalls > maxCurlShare) {
    stats.droppedCurlHeavy++;
    continue;
  }

  // Drop entries where an observation looks like a hard failure (Connection
  // refused, NXDOMAIN, timeout) but the very next assistant message claims
  // success (vulnerable / confirmed / exploited / bypass worked). Those cases
  // train the model to hallucinate findings from failing tool output.
  const contradiction = hasContradiction(entry);
  if (contradiction) {
    stats.droppedContradiction = (stats.droppedContradiction || 0) + 1;
    continue;
  }

  // Drop entries where post-observation analysis names a tool that was NOT
  // in the immediately preceding tool_call AND cannot be explained as a
  // recap of an earlier phase. This is the causal-attribution filter.
  const attribErr = attributionError(entry);
  if (attribErr) {
    stats.droppedAttribution = (stats.droppedAttribution || 0) + 1;
    continue;
  }

  stats.kept++;
  scoreSumOut += overall;

  filteredOut.write(JSON.stringify(entry) + "\n");
  qwenOut.write(JSON.stringify(toQwenChatML(entry)) + "\n");
  sharegptOut.write(JSON.stringify(toShareGPT(entry)) + "\n");

  for (const t of entry.metadata.tools_used) stats.toolDist[t] = (stats.toolDist[t] || 0) + 1;
  stats.categoryDist[entry.metadata.category] = (stats.categoryDist[entry.metadata.category] || 0) + 1;
  stats.difficultyDist[entry.metadata.difficulty] = (stats.difficultyDist[entry.metadata.difficulty] || 0) + 1;
}

filteredOut.end();
qwenOut.end();
sharegptOut.end();

await Promise.all([
  new Promise(r => filteredOut.on("close", r)),
  new Promise(r => qwenOut.on("close", r)),
  new Promise(r => sharegptOut.on("close", r)),
]);

stats.avgScoreIn = Math.round((scoreSumIn / lines.length) * 1000) / 1000;
stats.avgScoreOut = stats.kept ? Math.round((scoreSumOut / stats.kept) * 1000) / 1000 : 0;

writeFileSync(statsPath, JSON.stringify(stats, null, 2));
console.error(JSON.stringify(stats, null, 2));
console.error(`\n[filter] wrote:\n  ${filteredPath}\n  ${qwenPath}\n  ${sharegptPath}\n  ${statsPath}`);

// ---------- scrubbers, contradiction check, and format converters ----------


// Replace residual 'target.com' references (that leaked through generation) with
// the entry's actual domain inferred from the first human turn. Falls back to a
// stable synthetic domain so no placeholder survives into the training file.
function scrubPlaceholders(entry) {
  const human = entry.conversations.find(m => m.from === "human")?.value || "";
  const match = human.match(/https?:\/\/([\w.-]+)/) || human.match(/recon on ([\w.-]+)/i);
  const domain = (match && match[1] && !match[1].includes("target.com"))
    ? match[1].replace(/^(www|api|app|admin|corp|shop|auth)\./, "")
    : `acme-${entry.metadata.scenario_id.slice(0, 6)}.example`;

  const replaceIn = (s) => typeof s === "string"
    ? s.replace(/[\w-]*\.?target\.com/g, domain)
    : s;

  entry.conversations = entry.conversations.map(m => ({
    ...m,
    value: replaceIn(m.value),
    thinking: replaceIn(m.thinking),
    tool_calls: m.tool_calls?.map(tc => ({
      ...tc,
      arguments: Object.fromEntries(
        Object.entries(tc.arguments || {}).map(([k, v]) => [k, replaceIn(v)])
      ),
    })),
    tool_results: m.tool_results?.map(tr => ({ ...tr, output: replaceIn(tr.output) })),
  }));
  return entry;
}



function toQwenChatML(entry) {
  const messages = [];
  for (const m of entry.conversations) {
    if (m.from === "system") {
      messages.push({ role: "system", content: m.value });
    } else if (m.from === "human") {
      messages.push({ role: "user", content: m.value });
    } else if (m.from === "gpt") {
      // Post-processor already inlines <think> and <tool_call> into m.value when
      // thinkingStyle is "inline", so we pass the value through verbatim.
      // Fallback: if m.thinking is still present (non-inline style), wrap it.
      let content = m.value;
      if (m.thinking && !content.includes("<think>")) {
        content = `<think>\n${m.thinking}\n</think>\n\n${content}`;
      }
      if (m.tool_calls?.length && !content.includes("<tool_call>")) {
        const toolBlocks = m.tool_calls
          .map(tc => `<tool_call>\n${JSON.stringify({ name: tc.name, arguments: tc.arguments })}\n</tool_call>`)
          .join("\n");
        content = `${content}\n${toolBlocks}`;
      }
      messages.push({ role: "assistant", content });
    } else if (m.from === "tool" || m.from === "observation") {
      // Post-processor renames 'tool' → 'observation'; handle either.
      const observations = m.tool_results?.length
        ? m.tool_results.map(r => `<tool_response>\n${r.output}\n</tool_response>`).join("\n")
        : `<tool_response>\n${m.value}\n</tool_response>`;
      messages.push({ role: "observation", content: observations });
    }
  }
  return { messages, metadata: entry.metadata };
}

function toShareGPT(entry) {
  return {
    id: entry.id,
    conversations: entry.conversations.map(m => ({ from: m.from, value: m.value })),
  };
}
