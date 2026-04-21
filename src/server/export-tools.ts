// MCP Tool Handlers: Export and Merge datasets

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import * as fs from "fs";
import * as fsp from "fs/promises";
import * as path from "path";

export function registerExportTools(server: McpServer) {
  server.tool(
    "export_for_training",
    "Convert a PentesterFlow dataset to a specific training format. Handles Qwen tool roles, thinking blocks, and token limits.",
    {
      input_path: z.string().describe("Path to the source JSONL dataset"),
      output_format: z.enum(["chatml_qwen", "sharegpt", "openai", "alpaca", "chatml_generic"]).default("chatml_qwen").describe("Target format. 'chatml_qwen' = optimized for Qwen3.5."),
      output_path: z.string().optional().describe("Custom output path"),
      max_tokens: z.number().default(0).describe("Max estimated tokens per entry (0 = no limit)"),
      filter_thinking: z.enum(["include", "exclude", "only"]).default("include").describe("How to handle thinking blocks"),
    },
    async (args) => {
      try {
        const content = await fsp.readFile(args.input_path, "utf-8");
        const lines = content.trim().split("\n");
        const outputPath = args.output_path || args.input_path.replace(".jsonl", `_${args.output_format}.jsonl`);
        const writeStream = fs.createWriteStream(outputPath);
        let count = 0, skippedThinking = 0, truncated = 0;

        for (const line of lines) {
          const entry = JSON.parse(line);
          if (args.filter_thinking === "only" && !entry.metadata?.has_thinking) { skippedThinking++; continue; }
          if (args.filter_thinking === "exclude" && entry.metadata?.has_thinking) { skippedThinking++; continue; }

          let formatted: any;

          switch (args.output_format) {
            case "chatml_qwen": {
              const messages: any[] = [];
              for (const msg of entry.conversations) {
                let role: string;
                if (msg.from === "gpt") role = "assistant";
                else if (msg.from === "human") role = "user";
                else if (msg.from === "tool" || msg.from === "observation") role = "observation";
                else role = msg.from;

                let msgContent = msg.value || "";
                if (msg.thinking && args.filter_thinking !== "exclude" && !msgContent.includes("<think>")) {
                  msgContent = `<think>\n${msg.thinking}\n</think>\n\n${msgContent}`;
                }

                const inlineToolCallCount = (msgContent.match(/<tool_call>/g) || []).length;
                if (role === "assistant" && msg.tool_calls?.length > 0 && inlineToolCallCount < msg.tool_calls.length) {
                  msgContent += "\n\n" + msg.tool_calls.map((tc: any) =>
                    `<tool_call>\n{"name": "${tc.name}", "arguments": ${JSON.stringify(tc.arguments)}}\n</tool_call>`
                  ).join("\n");
                }
                if (role === "observation" && msg.tool_results?.length > 0) {
                  msgContent = msg.tool_results.map((r: any) =>
                    `<tool_response>\n{"name": "${r.name}", "output": ${JSON.stringify(r.output)}}\n</tool_response>`
                  ).join("\n");
                }
                messages.push({ role, content: msgContent });
              }
              formatted = { messages };
              break;
            }
            case "chatml_generic": {
              formatted = {
                messages: entry.conversations
                  .filter((msg: any) => msg.from !== "tool" && msg.from !== "observation")
                  .map((msg: any) => {
                    const role = msg.from === "gpt" ? "assistant" : msg.from === "human" ? "user" : msg.from;
                    let c = "";
                    if (msg.thinking && args.filter_thinking !== "exclude") c += `<think>\n${msg.thinking}\n</think>\n\n`;
                    c += msg.value || "";
                    if (msg.tool_calls) c += "\n\n" + msg.tool_calls.map((tc: any) => `Tool: ${tc.name}\nCommand: ${tc.arguments?.command || JSON.stringify(tc.arguments)}`).join("\n\n");
                    return { role, content: c };
                  }),
              };
              break;
            }
            case "sharegpt": {
              formatted = {
                conversations: entry.conversations.map((msg: any) => {
                  const from = msg.from === "observation" ? "tool" : msg.from;
                  let value = "";
                  if (msg.thinking && args.filter_thinking !== "exclude") value += `<think>\n${msg.thinking}\n</think>\n\n`;
                  value += msg.value || "";
                  return { from, value, ...(msg.tool_calls ? { tool_calls: msg.tool_calls } : {}) };
                }),
              };
              break;
            }
            case "openai": {
              const openaiMsgs: any[] = [];
              for (const msg of entry.conversations) {
                if (msg.from === "tool" || msg.from === "observation") continue;
                const role = msg.from === "gpt" ? "assistant" : msg.from === "human" ? "user" : msg.from;
                let c = "";
                if (msg.thinking && args.filter_thinking !== "exclude") c += `<think>\n${msg.thinking}\n</think>\n\n`;
                c += msg.value || "";
                const m: any = { role, content: c };
                if (msg.tool_calls) m.tool_calls = msg.tool_calls.map((tc: any) => ({ id: tc.id, type: "function", function: { name: tc.name, arguments: JSON.stringify(tc.arguments) } }));
                openaiMsgs.push(m);
              }
              formatted = { messages: openaiMsgs };
              break;
            }
            case "alpaca": {
              const userMsg = entry.conversations.find((m: any) => m.from === "human");
              const assistantMsg = entry.conversations.find((m: any) => m.from === "gpt");
              const systemMsg = entry.conversations.find((m: any) => m.from === "system");
              let output = "";
              if (assistantMsg?.thinking && args.filter_thinking !== "exclude") output += `<think>\n${assistantMsg.thinking}\n</think>\n\n`;
              output += assistantMsg?.value || "";
              formatted = { instruction: userMsg?.value || "", input: "", output, system: systemMsg?.value || "" };
              break;
            }
          }

          if (args.max_tokens > 0) {
            const est = Math.ceil(JSON.stringify(formatted).length / 3.5);
            if (est > args.max_tokens) {
              const arr = formatted.messages || formatted.conversations;
              if (arr && arr.length > 4) {
                while (arr.length > 4 && Math.ceil(JSON.stringify(formatted).length / 3.5) > args.max_tokens) arr.splice(-1, 1);
                truncated++;
              }
            }
          }

          writeStream.write(JSON.stringify(formatted) + "\n");
          count++;
        }

        await new Promise<void>((resolve, reject) => { writeStream.end(() => resolve()); writeStream.on("error", reject); });

        const formatInfo: Record<string, string> = {
          chatml_qwen: "Qwen3.5 Native: system/user/assistant/observation roles, <think> tags, <tool_call>/<tool_response> tags",
          chatml_generic: "Generic ChatML: system/user/assistant roles, tool outputs inlined",
          sharegpt: "ShareGPT: system/human/gpt/tool roles, compatible with LLaMA-Factory/Axolotl",
          openai: "OpenAI: system/user/assistant with function_call format",
          alpaca: "Alpaca: single-turn instruction/input/output format",
        };

        return {
          content: [{
            type: "text",
            text: `Exported ${count} entries to ${args.output_format}.\nOutput: ${outputPath}\n${skippedThinking > 0 ? `Skipped: ${skippedThinking} (thinking filter)\n` : ""}${truncated > 0 ? `Truncated: ${truncated} (token limit)\n` : ""}\n${formatInfo[args.output_format] || ""}`,
          }],
        };
      } catch (error) {
        return { content: [{ type: "text", text: `Error exporting dataset: ${error}` }], isError: true };
      }
    }
  );

  server.tool(
    "merge_datasets",
    "Merge multiple PentesterFlow datasets into a single file with deduplication and balanced sampling.",
    {
      input_paths: z.array(z.string()).min(2).describe("Paths to JSONL dataset files to merge"),
      output_path: z.string().describe("Output path for the merged dataset"),
      deduplicate: z.boolean().default(true).describe("Remove duplicate entries by ID"),
      max_entries: z.number().optional().describe("Maximum entries in merged dataset"),
      balance_categories: z.boolean().default(false).describe("Balance entries across categories"),
    },
    async (args) => {
      try {
        const allEntries: any[] = [];
        const seenIds = new Set<string>();
        const sourceCounts: Record<string, number> = {};

        for (const inputPath of args.input_paths) {
          const content = await fsp.readFile(inputPath, "utf-8");
          const lines = content.trim().split("\n");
          let added = 0;
          for (const line of lines) {
            try {
              const entry = JSON.parse(line);
              if (args.deduplicate && seenIds.has(entry.id)) continue;
              seenIds.add(entry.id);
              allEntries.push(entry);
              added++;
            } catch { /* skip */ }
          }
          sourceCounts[path.basename(inputPath)] = added;
        }

        let finalEntries = allEntries;
        if (args.balance_categories) {
          const byCategory: Record<string, any[]> = {};
          for (const entry of allEntries) { const cat = entry.metadata?.category || "unknown"; (byCategory[cat] ??= []).push(entry); }
          const maxPerCat = args.max_entries ? Math.ceil(args.max_entries / Object.keys(byCategory).length) : Math.max(...Object.values(byCategory).map(a => a.length));
          finalEntries = [];
          for (const entries of Object.values(byCategory)) finalEntries.push(...entries.sort(() => Math.random() - 0.5).slice(0, maxPerCat));
        }
        if (args.max_entries && finalEntries.length > args.max_entries) finalEntries = finalEntries.sort(() => Math.random() - 0.5).slice(0, args.max_entries);

        const writeStream = fs.createWriteStream(args.output_path);
        for (const entry of finalEntries) {
          const ok = writeStream.write(JSON.stringify(entry) + "\n");
          if (!ok) await new Promise<void>(r => writeStream.once("drain", r));
        }
        await new Promise<void>((resolve, reject) => { writeStream.end(() => resolve()); writeStream.on("error", reject); });

        return {
          content: [{
            type: "text",
            text: `Merged ${finalEntries.length} entries.\nOutput: ${args.output_path}\n\nSources:\n${Object.entries(sourceCounts).map(([f, c]) => `  ${f}: ${c}`).join("\n")}`,
          }],
        };
      } catch (error) {
        return { content: [{ type: "text", text: `Error merging: ${error}` }], isError: true };
      }
    }
  );
}
