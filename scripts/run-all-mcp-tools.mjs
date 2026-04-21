// Exercises every MCP tool in the OffensiveSET server by spawning the real
// dist/index.js over stdio and calling each tool through the MCP SDK client.
// This is exactly how Claude Desktop / Claude Code would drive the server.

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { resolve } from "node:path";
import { readdirSync, statSync } from "node:fs";

const cwd = process.cwd();
const FILTERED = resolve(cwd, "datasets/pentesterflow_v2_dataset_2026-04-21T02-21-05_filtered.jsonl");

function banner(s) {
  console.log("\n" + "═".repeat(70));
  console.log("  " + s);
  console.log("═".repeat(70));
}

function textOf(r) {
  return r.content.map(c => (c.type === "text" ? c.text : "")).join("\n");
}

const transport = new StdioClientTransport({
  command: "node",
  args: [resolve(cwd, "dist/index.js")],
});
const client = new Client({ name: "offensiveset-runner", version: "1.0.0" });
await client.connect(transport);

try {
  banner("Available MCP tools");
  const toolsResp = await client.listTools();
  for (const t of toolsResp.tools) console.log(`  • ${t.name.padEnd(24)} ${t.description.slice(0, 70)}`);

  // 1. list_scenarios
  banner("list_scenarios — top-level category summary");
  const listScen = await client.callTool({ name: "list_scenarios", arguments: {} });
  console.log(textOf(listScen).split("\n").slice(0, 20).join("\n"));

  // 2. list_tools
  banner("list_tools — pentesting tool inventory (first 25 lines)");
  const listTools = await client.callTool({ name: "list_tools", arguments: {} });
  console.log(textOf(listTools).split("\n").slice(0, 25).join("\n"));

  // 3. preview_entry — one generated example
  banner("preview_entry — sample NoSQL injection scenario");
  const preview = await client.callTool({
    name: "preview_entry",
    arguments: { scenario_id: "nosql-injection-mongodb" },
  });
  console.log(textOf(preview).slice(0, 1200));
  console.log("... [truncated]");

  // 4. generate_dataset — V1 for comparison (small run)
  banner("generate_dataset (V1) — 300 entries for merge comparison");
  const genV1 = await client.callTool({
    name: "generate_dataset",
    arguments: {
      count: 300,
      output_dir: "./datasets",
      include_thinking: true,
    },
  });
  console.log(textOf(genV1));

  // Find the new v1 file
  const all = readdirSync(resolve(cwd, "datasets"))
    .filter(f => f.endsWith(".jsonl") && !f.includes("chatml") && !f.includes("sharegpt") && !f.includes("filtered"))
    .map(f => ({ f, t: statSync(resolve(cwd, "datasets", f)).mtimeMs }))
    .sort((a, b) => b.t - a.t);
  const v1Path = all.find(x => !x.f.includes("v2"))?.f
    ? resolve(cwd, "datasets", all.find(x => !x.f.includes("v2")).f)
    : resolve(cwd, "datasets", all[0].f); // fallback
  console.log("V1 file:", v1Path);

  // 5. get_dataset_stats — on the filtered v2 dataset
  banner("get_dataset_stats — filtered 6,557-entry V2 dataset");
  const stats = await client.callTool({
    name: "get_dataset_stats",
    arguments: { file_path: FILTERED },
  });
  console.log(textOf(stats));

  // 6. validate_dataset
  banner("validate_dataset — schema + placeholder + role checks");
  const validate = await client.callTool({
    name: "validate_dataset",
    arguments: { file_path: FILTERED, strict: false },
  });
  console.log(textOf(validate));

  // 7. quality_score — A-F grading
  banner("quality_score — deep quality analysis (A-F grade)");
  const quality = await client.callTool({
    name: "quality_score",
    arguments: { file_path: FILTERED, sample_size: 1000 },
  });
  console.log(textOf(quality));

  // 8. merge_datasets — v1 + v2_filtered
  banner("merge_datasets — combine V1 (300) + V2_filtered (6,557)");
  const mergedPath = resolve(cwd, "datasets/merged_v1_v2.jsonl");
  const merge = await client.callTool({
    name: "merge_datasets",
    arguments: {
      input_paths: [v1Path, FILTERED],
      output_path: mergedPath,
      deduplicate: true,
      balance_categories: false,
    },
  });
  console.log(textOf(merge));

  // 9. export_for_training — all 5 formats on the filtered dataset
  banner("export_for_training — produce all 5 training formats");
  const formats = ["chatml_qwen", "chatml_generic", "sharegpt", "openai", "alpaca"];
  for (const fmt of formats) {
    const exp = await client.callTool({
      name: "export_for_training",
      arguments: { input_path: FILTERED, output_format: fmt },
    });
    console.log(`\n[${fmt}]`);
    console.log(textOf(exp));
  }

  // 10. quality_score on merged
  banner("quality_score on merged V1+V2 dataset");
  const qualityMerged = await client.callTool({
    name: "quality_score",
    arguments: { file_path: mergedPath, sample_size: 1000 },
  });
  console.log(textOf(qualityMerged));
} finally {
  await client.close();
}
