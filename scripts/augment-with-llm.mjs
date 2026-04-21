// LLM augmentation pipeline for OffensiveSET datasets.
//
// WHAT IT DOES
//   Reads a JSONL dataset, samples entries, and asks a teacher LLM (Claude by default)
//   to rewrite the curl-heavy and low-variance parts with more realistic tool usage,
//   richer thinking blocks, and more natural analyst prose. The scenario spec, CVE
//   references, and overall structure are preserved — the LLM only fills in detail.
//
// WHY
//   OffensiveSET's procedural generator excels at structure but plateaus on realism.
//   An LLM teacher fills in the gap without replacing the grounded scenario data.
//
// COST
//   Claude Sonnet 4.6 is ~$3/M input, ~$15/M output. A 6k-token pentest convo costs
//   ~$0.05 to rewrite. 1000 entries ≈ $50. 10k entries ≈ $500. Use --sample to bound.
//
// REQUIREMENTS
//   npm i @anthropic-ai/sdk
//   export ANTHROPIC_API_KEY=sk-ant-...
//
// USAGE
//   node scripts/augment-with-llm.mjs \
//     --input  ./datasets/pentesterflow_v2_dataset_..._filtered.jsonl \
//     --output ./datasets/pentesterflow_v2_augmented.jsonl \
//     --sample 500                 # augment only 500 entries
//     --model claude-sonnet-4-6    # or claude-haiku-4-5 for cheaper
//     --concurrency 5
//
// LEGAL NOTE
//   Anthropic's ToS prohibits using outputs to train a competing model. For research
//   / personal fine-tunes this is generally fine; review the ToS before shipping.
//   For zero-ToS-risk augmentation, swap in a local teacher (Qwen3.5-72B, Llama 3.3).
//
// STATUS: intentionally NOT run. Set your API key and invoke manually.

import { readFileSync, createWriteStream } from "node:fs";
import { resolve } from "node:path";

const args = parseArgs(process.argv.slice(2));
const inputPath = resolve(args.input || "./datasets/pentesterflow_v2_dataset_latest_filtered.jsonl");
const outputPath = resolve(args.output || "./datasets/pentesterflow_v2_augmented.jsonl");
const sample = Number(args.sample || 100);
const concurrency = Number(args.concurrency || 5);
const model = args.model || "claude-sonnet-4-6";

if (!process.env.ANTHROPIC_API_KEY) {
  console.error("ANTHROPIC_API_KEY is not set. Export it before running.");
  process.exit(2);
}

// Lazy import so file can be read/inspected without the SDK installed.
let Anthropic;
try {
  Anthropic = (await import("@anthropic-ai/sdk")).default;
} catch {
  console.error("@anthropic-ai/sdk is not installed. Run: npm i @anthropic-ai/sdk");
  process.exit(2);
}
const client = new Anthropic();

const AUGMENT_SYSTEM_PROMPT = `You are a senior offensive security engineer. You are given a synthetic
pentest conversation generated from a template. Rewrite it to be more realistic
without changing its structure or metadata.

Rules:
1. Preserve every tool_call / observation / assistant boundary exactly. Do not add or remove turns.
2. Replace curl-heavy enumeration with more appropriate tools (httpx, nuclei, ffuf, feroxbuster, arjun, etc.) where the workflow supports it.
3. Expand <think> blocks to include hypothesis, elimination, and pivoting — at least 200 words each when present.
4. Keep the final report section (CVSS, CWE, remediation) and do not weaken its specificity.
5. Return JSON only: { "conversations": [...] } with the same ShareGPT schema.
6. Never reference Claude, Anthropic, OpenAI, or any LLM identity.`;

const lines = readFileSync(inputPath, "utf8").split("\n").filter(Boolean);
const chosen = lines.slice(0, sample);
console.error(`[augment] input=${lines.length} sample=${chosen.length} model=${model}`);

const out = createWriteStream(outputPath);
let inFlight = 0;
let done = 0;
const queue = [...chosen];

await new Promise((resolveAll) => {
  const tick = () => {
    while (inFlight < concurrency && queue.length > 0) {
      const line = queue.shift();
      inFlight++;
      augmentOne(line)
        .then((augmented) => {
          out.write(JSON.stringify(augmented) + "\n");
        })
        .catch((err) => {
          console.error(`[augment] failed for one entry: ${err.message} — keeping original`);
          out.write(line + "\n");
        })
        .finally(() => {
          inFlight--;
          done++;
          if (done % 10 === 0) console.error(`[augment] ${done}/${chosen.length}`);
          if (queue.length === 0 && inFlight === 0) {
            out.end();
            resolveAll();
          } else {
            tick();
          }
        });
    }
  };
  tick();
});

console.error(`[augment] done — wrote ${outputPath}`);

async function augmentOne(line) {
  const entry = JSON.parse(line);
  const msg = await client.messages.create({
    model,
    max_tokens: 8192,
    system: AUGMENT_SYSTEM_PROMPT,
    messages: [
      {
        role: "user",
        content: `Rewrite the following conversation. Return only JSON:\n\n${JSON.stringify(entry, null, 2)}`,
      },
    ],
  });
  const text = msg.content.map((b) => (b.type === "text" ? b.text : "")).join("");
  const jsonMatch = text.match(/\{[\s\S]*\}/);
  if (!jsonMatch) throw new Error("no JSON in response");
  const parsed = JSON.parse(jsonMatch[0]);
  return {
    ...entry,
    conversations: parsed.conversations || entry.conversations,
    metadata: { ...entry.metadata, augmented_by: model, augmented_at: new Date().toISOString() },
  };
}

function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i += 2) {
    out[argv[i].replace(/^--/, "")] = argv[i + 1];
  }
  return out;
}
