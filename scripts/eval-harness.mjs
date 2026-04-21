// Eval harness for OffensiveSET training-readiness.
//
// Checks that matter for tool-use fine-tuning but aren't captured by
// validate_dataset / quality_score:
//
//   1. Foreign-tool-mention-in-post-analysis
//      For each post-observation assistant turn, are the tool names it
//      mentions a subset of the tools that actually ran in the preceding
//      tool_call? If not, the model is being trained to attribute findings
//      to tools that were not invoked.
//
//   2. Unreachable-observation / mismatched-thinking
//      When an observation contains a hard-failure signature (Connection
//      refused, NXDOMAIN, timeout), does the next assistant turn's <think>
//      block still claim the endpoint was reachable / rate-limited /
//      filtered? Those are causally wrong reasoning paths.
//
//   3. Scenario coverage loss after filtering
//      Given raw and filtered datasets, report which scenario_ids survive
//      filtering and which are wiped out. Filtering curl-heavy entries
//      shouldn't be deleting whole attack classes.
//
// Usage:
//   node scripts/eval-harness.mjs \
//     --raw      ./datasets/pentesterflow_v2_dataset_<t>.jsonl \
//     --filtered ./datasets/pentesterflow_v2_dataset_<t>_filtered.jsonl
//
// Exits non-zero when any check fails its threshold.

import { readFileSync, existsSync } from "node:fs";
import { resolve } from "node:path";

const args = parseArgs(process.argv.slice(2));
const rawPath = args.raw ? resolve(args.raw) : null;
const filteredPath = args.filtered ? resolve(args.filtered) : null;
const sampleReport = Number(args["sample-report"] || 5);

// Flag only PURELY unreachable observations. A mixed-signal obs — e.g. a
// timeout on one request but a 200/403 on another in the same phase — is
// ambiguous; the think can legitimately attribute to either signal. Keep
// the eval tight on clear-cut cases.
const FAIL_RX = /Connection refused|Failed to connect|Could not resolve|No route to host|Host unreachable|Name or service not known|NXDOMAIN/i;
// Recognize application-layer success signals across tool output styles:
//   - raw HTTP:         "HTTP/1.1 200 OK" / "HTTP/2 403 Forbidden"
//   - httpx bracketed:  "[200]" / "[301]" / "[404 Not Found]"
//   - response headers: "Content-Type: ...", "Server: nginx"
//   - JSON body signals: {"status": 200, ...}
const SUCCESS_SIGNAL_RX = /\bHTTP\/[\d.]+\s+(200|201|204|301|302|304|400|401|403|404|405|500|502|503)\b|\[(200|201|204|301|302|304|400|401|403|404|405|500|502|503)(\s+[A-Za-z][\w\s]*?)?\]|Content-Type:|Server:\s+\w+|"status"\s*:\s*(200|201|204|301|302|400|401|403|404)/i;
const KNOWN_TOOLS = new Set([
  "nmap","sqlmap","ffuf","nuclei","httpx","curl","nikto","wfuzz","dalfox","gobuster",
  "arjun","subfinder","amass","jwt_tool","hydra","metasploit","katana","rustscan",
  "linpeas","nosqlmap","commix","ssrfmap","crlfuzz","corsy","paramspider","aws_cli",
  "semgrep","trufflehog","testssl","kubectl","report_generator","python_script","bash",
  "feroxbuster","dirsearch","dnsx","puredns","gau","gf","secretfinder","linkfinder",
  "kiterunner","caido","interactsh",
]);
const MENTION_RX = new RegExp(`\\b(${[...KNOWN_TOOLS].sort((a, b) => b.length - a.length).join("|")})\\b`, "gi");

const REACHABLE_CLAIM_RX = /\b(rate[- ]?limit(ed|ing)?|WAF (blocked|caught)|input (filter|validation)|no injectable|endpoint (properly |correctly )?(handles|validated|sanit)|request was blocked|filter(ed)? the payload)\b/i;

// Per-class expectations for check 2 expansion. Given an observed failure
// class, THIS is what the reasoning should lean into; anything else from the
// incompatible list is a mismatch.
const EXPECTED_BY_CLASS = {
  unreachable: [/unreachable|offline|connection refused|could not resolve|no route to host|NXDOMAIN/i],
  timeout: [/timed out|timeout|no response|request never returned/i],
  ratelimited: [/rate[- ]?limit(ed|ing)?|throttl|HTTP 429|too many requests/i],
  blocked: [/WAF|blocked by|input filter|input validation|denied by policy|security control/i],
};
const INCOMPATIBLE_BY_CLASS = {
  unreachable: [/rate[- ]?limit(ed|ing)?|WAF (blocked|caught)|input (filter|validation)|filter(ed)? the payload/i],
  timeout: [/WAF (blocked|caught)|rate[- ]?limit(ed|ing)? (kicked|blocked)/i],
  ratelimited: [/unreachable|offline|could not resolve/i],
  blocked: [/unreachable|offline|could not resolve|timed out/i],
};
function classifyFailureStrict(obs) {
  if (/Connection refused|Failed to connect|Could not resolve|No route to host|Host unreachable|NXDOMAIN/i.test(obs)) return "unreachable";
  if (/\b429\b|rate[- ]?limit|too many requests|throttl/i.test(obs)) return "ratelimited";
  if (/\b403\b|WAF|blocked by|cloudflare|akamai|imperva|mod_security|denied by policy/i.test(obs)) return "blocked";
  if (/timed out|timeout|operation timed/i.test(obs)) return "timeout";
  return null;
}

const report = { foreignTool: null, unreachableMismatch: null, coverage: null };
let anyFail = false;

// ---------- Check 1 + 2 ----------
if (filteredPath && existsSync(filteredPath)) {
  const foreignExamples = [];
  const strictForeignExamples = [];
  const mismatchExamples = [];
  const lines = readFileSync(filteredPath, "utf8").split("\n").filter(Boolean);
  let postAnalysisTotal = 0, postAnalysisForeign = 0, postAnalysisNoTool = 0;
  let strictForeignCount = 0, spotlightRecap = 0;
  let hardFailObs = 0, hardFailMismatch = 0;

  for (const l of lines) {
    const o = JSON.parse(l);
    const msgs = o.conversations;
    // Conversation-wide set of tools that ever ran — narrative that references
    // a tool from an earlier phase is contextually fine (analyst recapping
    // prior evidence). Only tools that never ran anywhere in this conversation
    // count as foreign mentions.
    const convToolCalls = new Set();
    for (const mm of msgs) if (mm.tool_calls) for (const tc of mm.tool_calls) if (tc.name) convToolCalls.add(tc.name.toLowerCase());

    for (let i = 0; i < msgs.length - 1; i++) {
      const m = msgs[i];
      if (m.from !== "tool" && m.from !== "observation") continue;
      // Which tool(s) were actually called? The immediately preceding gpt msg.
      let actualTools = new Set();
      for (let k = i - 1; k >= 0; k--) {
        if (msgs[k].from === "gpt" && msgs[k].tool_calls?.length) {
          for (const tc of msgs[k].tool_calls) if (tc.name) actualTools.add(tc.name.toLowerCase());
          break;
        }
        if (msgs[k].from === "gpt") break;
      }

      // Next gpt message after the observation (post-analysis)
      const next = msgs.slice(i + 1).find(mm => mm.from === "gpt");
      if (!next) continue;
      postAnalysisTotal++;

      // Strip <think> blocks, ```code``` fences, <tool_call>...</tool_call> blobs.
      // Tool names inside code blocks are *reference commands* (e.g. a PoC
      // script showing what a pentester could run), not claims about what
      // actually executed this turn — don't count those as foreign.
      const thinkText = ((next.value || "").match(/<think>([\s\S]*?)<\/think>/) || [])[1] || next.thinking || "";
      const bodyText = (next.value || "")
        .replace(/<think>[\s\S]*?<\/think>/g, "")
        .replace(/```[\s\S]*?```/g, "")
        .replace(/<tool_call>[\s\S]*?<\/tool_call>/g, "")
        .replace(/<tool_response>[\s\S]*?<\/tool_response>/g, "");

      const mentioned = new Set([...(bodyText.match(MENTION_RX) || [])].map(s => s.toLowerCase()));
      if (mentioned.size === 0) {
        postAnalysisNoTool++;
      } else {
        // Two scores: lenient (conversation-wide) and strict (only the
        // immediately preceding tool_call). Lenient tolerates analyst recap
        // of earlier phases; strict is the one that matters for teaching
        // causal attribution to the model.
        const foreign = [...mentioned].filter(t => !convToolCalls.has(t));
        if (foreign.length > 0) {
          postAnalysisForeign++;
          if (foreignExamples.length < sampleReport) {
            foreignExamples.push({ id: o.id, actual: [...actualTools], conv: [...convToolCalls], mentioned: [...mentioned], foreign, snippet: bodyText.slice(0, 220) });
          }
        }
        const strictForeign = [...mentioned].filter(t => !actualTools.has(t));
        if (strictForeign.length > 0 && actualTools.size > 0) {
          // Classify: does the bodyText frame this as a recap of an earlier
          // phase? Those still drift, but we annotate them separately so
          // the reader can judge.
          const isRecap = /(earlier|earlier result|earlier scan|consistent with what|what .* showed|prior|prior phase|previous run|from the first phase)/i.test(bodyText);
          if (isRecap) spotlightRecap++;
          strictForeignCount++;
          if (strictForeignExamples.length < sampleReport) {
            strictForeignExamples.push({
              id: o.id, actual: [...actualTools], mentioned: [...mentioned],
              strictForeign, recap: isRecap, snippet: bodyText.slice(0, 220),
            });
          }
        }
      }

      // Expanded check 2 — classify obs into unreachable/timeout/ratelimited/
      // blocked. For each class, check that thinking doesn't use reasoning
      // incompatible with that class. We skip mixed-signal observations
      // (e.g. timeout + 200 OK) because either attribution is defensible.
      const obsText = (m.value || "") + (m.tool_results?.map(r => r.output).join("\n") || "");
      const obsClass = classifyFailureStrict(obsText);
      const isPure = obsClass && !SUCCESS_SIGNAL_RX.test(obsText);
      if (isPure) {
        hardFailObs++;
        const incompatible = INCOMPATIBLE_BY_CLASS[obsClass];
        const hit = incompatible?.some(rx => rx.test(thinkText));
        if (hit) {
          hardFailMismatch++;
          if (mismatchExamples.length < sampleReport) {
            mismatchExamples.push({
              id: o.id,
              obsClass,
              obs: obsText.slice(0, 160),
              think: thinkText.slice(0, 300),
            });
          }
        }
      }
    }
  }

  report.foreignTool = {
    post_analysis_turns: postAnalysisTotal,
    // Lenient: conversation-wide — drift ok if a prior phase ran the tool.
    mentioning_foreign_tool: postAnalysisForeign,
    pct_foreign: +(postAnalysisForeign / Math.max(postAnalysisTotal, 1) * 100).toFixed(2),
    // Strict: mentioning a tool NOT in the immediately preceding tool_calls.
    // This is what actually teaches causal attribution.
    strict_foreign_count: strictForeignCount,
    pct_strict_foreign: +(strictForeignCount / Math.max(postAnalysisTotal, 1) * 100).toFixed(2),
    strict_recap: spotlightRecap,
    strict_non_recap: strictForeignCount - spotlightRecap,
    pct_strict_non_recap: +((strictForeignCount - spotlightRecap) / Math.max(postAnalysisTotal, 1) * 100).toFixed(2),
    mentioning_no_tool: postAnalysisNoTool,
    pct_no_tool: +(postAnalysisNoTool / Math.max(postAnalysisTotal, 1) * 100).toFixed(2),
    examples: foreignExamples,
    strict_examples: strictForeignExamples,
  };
  report.unreachableMismatch = {
    hard_failure_observations: hardFailObs,
    with_incompatible_thinking: hardFailMismatch,
    pct: +(hardFailMismatch / Math.max(hardFailObs, 1) * 100).toFixed(2),
    examples: mismatchExamples,
  };
  if (report.foreignTool.pct_foreign > 10) anyFail = true;
  // Strict non-recap threshold: the drift that isn't just analyst recap must
  // stay under 3% or the model will learn to hallucinate tools that never ran.
  if (report.foreignTool.pct_strict_non_recap > 3) anyFail = true;
  if (report.unreachableMismatch.pct > 10) anyFail = true;
}

// ---------- Check 3: scenario coverage loss ----------
if (rawPath && filteredPath && existsSync(rawPath) && existsSync(filteredPath)) {
  const rawSet = new Set();
  const keptSet = new Set();
  const rawLines = readFileSync(rawPath, "utf8").split("\n").filter(Boolean);
  for (const l of rawLines) rawSet.add(JSON.parse(l).metadata?.scenario_id);
  const keptLines = readFileSync(filteredPath, "utf8").split("\n").filter(Boolean);
  for (const l of keptLines) keptSet.add(JSON.parse(l).metadata?.scenario_id);
  const lost = [...rawSet].filter(s => !keptSet.has(s));
  report.coverage = {
    scenarios_in_raw: rawSet.size,
    scenarios_in_filtered: keptSet.size,
    lost_after_filter: lost,
    lost_count: lost.length,
  };
  if (lost.length > 0) anyFail = true;
}

// ---------- Print report ----------
const line = "═".repeat(70);
console.log(line);
console.log("OffensiveSET — Training Readiness Eval");
console.log(line);

if (report.foreignTool) {
  const r = report.foreignTool;
  console.log("\n[1] Foreign tool mentions in post-observation analysis");
  console.log(`    post-observation gpt turns:       ${r.post_analysis_turns}`);
  console.log(`    LENIENT (conv-wide foreign):      ${r.mentioning_foreign_tool} (${r.pct_foreign}%)`);
  console.log(`    STRICT (not in preceding call):   ${r.strict_foreign_count} (${r.pct_strict_foreign}%)`);
  console.log(`      of which recap/reference:       ${r.strict_recap}`);
  console.log(`      of which non-recap drift:       ${r.strict_non_recap} (${r.pct_strict_non_recap}%)`);
  console.log(`    mentioning no tool at all:        ${r.mentioning_no_tool} (${r.pct_no_tool}%)`);
  if (r.strict_examples?.length) {
    console.log(`    strict-check example offenders (${r.strict_examples.length}):`);
    for (const ex of r.strict_examples) {
      console.log(`      - id=${ex.id} recap=${ex.recap}`);
      console.log(`        actual=[${ex.actual.join(",")}] mentioned=[${ex.mentioned.join(",")}] strict_foreign=[${ex.strictForeign.join(",")}]`);
      console.log(`        snippet: ${ex.snippet.replace(/\s+/g, " ")}`);
    }
  }
  const lenientPass = r.pct_foreign <= 10;
  const strictPass = r.pct_strict_non_recap <= 3;
  console.log(`    THRESHOLDS: lenient <=10%, strict non-recap <=3%`);
  console.log(`    RESULT: lenient ${lenientPass ? "PASS" : "FAIL"}, strict ${strictPass ? "PASS" : "FAIL"}`);
}

if (report.unreachableMismatch) {
  const r = report.unreachableMismatch;
  console.log("\n[2] Failure-class observation -> mismatched thinking (unreachable/timeout/blocked/ratelimited)");
  console.log(`    pure-failure observations:        ${r.hard_failure_observations}`);
  console.log(`    followed by incompatible <think>: ${r.with_incompatible_thinking} (${r.pct}%)`);
  if (r.examples.length) {
    console.log(`    example offenders (${r.examples.length}):`);
    for (const ex of r.examples) {
      console.log(`      - id=${ex.id} class=${ex.obsClass}`);
      console.log(`        obs:   ${ex.obs.replace(/\s+/g, " ")}`);
      console.log(`        think: ${ex.think.replace(/\s+/g, " ")}`);
    }
  }
  console.log(`    THRESHOLD: <= 10%   RESULT: ${r.pct <= 10 ? "PASS" : "FAIL"}`);
}

if (report.coverage) {
  const r = report.coverage;
  console.log("\n[3] Scenario coverage loss after filtering");
  console.log(`    raw scenarios:                    ${r.scenarios_in_raw}`);
  console.log(`    filtered scenarios:               ${r.scenarios_in_filtered}`);
  console.log(`    scenarios fully lost:             ${r.lost_count}`);
  if (r.lost_after_filter?.length) {
    for (const s of r.lost_after_filter) console.log(`      - ${s}`);
  }
  console.log(`    THRESHOLD: 0 lost   RESULT: ${r.lost_count === 0 ? "PASS" : "FAIL"}`);
}

console.log("\n" + line);
console.log(`OVERALL: ${anyFail ? "FAIL" : "PASS"}`);
console.log(line);
process.exit(anyFail ? 1 : 0);

function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i++) {
    const k = argv[i];
    if (!k.startsWith("--")) continue;
    out[k.slice(2)] = argv[i + 1];
    i++;
  }
  return out;
}
