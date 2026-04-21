// MCP Tool Handlers: Browse scenarios, tools, preview entries

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { listAvailableScenarios, generateDataset } from "../generators/v1-generator.js";
import { ALL_SCENARIOS } from "../templates/scenarios/index.js";
import { PENTESTING_TOOLS } from "../schemas/tools/index.js";
import { SeededRNG } from "../generators/outputs/index.js";
import { buildConversationV2 } from "../generators/v2/conversation.js";
import * as fsp from "fs/promises";
import * as os from "os";
import * as path from "path";

export function registerBrowseTools(server: McpServer) {
  server.tool(
    "list_scenarios",
    "List all available pentesting scenario templates with categories, difficulties, and tags.",
    {
      category: z.string().optional().describe("Filter by category"),
      difficulty: z.string().optional().describe("Filter by difficulty level"),
      tag: z.string().optional().describe("Filter by tag"),
    },
    async (args) => {
      const info = listAvailableScenarios();
      let scenarios = info.scenarios;
      if (args.category) scenarios = scenarios.filter(s => s.category.includes(args.category!));
      if (args.difficulty) scenarios = scenarios.filter(s => s.difficulty === args.difficulty);
      if (args.tag) scenarios = scenarios.filter(s => s.tags.includes(args.tag!));

      return {
        content: [{
          type: "text",
          text: `PentesterFlow Scenario Library\n\nTotal scenarios: ${info.total}\n\nCategories:\n${Object.entries(info.categories).map(([k, v]) => `  ${k}: ${v} scenarios`).join("\n")}\n\nDifficulty Distribution:\n${Object.entries(info.difficulties).map(([k, v]) => `  ${k}: ${v}`).join("\n")}\n\nAvailable Tags: ${info.tags.join(", ")}\n\n${scenarios.length > 0 ? `Scenarios${args.category || args.difficulty || args.tag ? " (filtered)" : ""}:\n${scenarios.map(s => `  [${s.difficulty.toUpperCase()}] ${s.id}: ${s.title} (${s.category}) [${s.tags.join(", ")}]`).join("\n")}` : "No scenarios match the filter."}`,
        }],
      };
    }
  );

  server.tool(
    "list_tools",
    "List all pentesting tools defined in the dataset schema with their categories and capabilities.",
    {
      category: z.string().optional().describe("Filter by tool category (recon, enumeration, scanning, exploitation, post_exploitation, reporting, utility)"),
    },
    async (args) => {
      let tools = PENTESTING_TOOLS;
      if (args.category) tools = tools.filter(t => t.category === args.category);

      return {
        content: [{
          type: "text",
          text: `PentesterFlow Tool Arsenal\n\nTotal tools: ${PENTESTING_TOOLS.length}\n\n${tools.map(t => `### ${t.name} [${t.category}]\n${t.description}\nParameters: ${Object.keys(t.parameters).join(", ")}\nExample: ${t.example_commands[0] || "N/A"}`).join("\n\n")}`,
        }],
      };
    }
  );

  server.tool(
    "preview_entry",
    "Generate and preview a single dataset entry for a specific scenario. Useful for quality inspection before generating the full dataset.",
    {
      scenario_id: z.string().optional().describe("Specific scenario ID to preview (use list_scenarios to see IDs)"),
      include_thinking: z.boolean().default(true).describe("Include thinking/reasoning blocks"),
    },
    async (args) => {
      const scenarios = ALL_SCENARIOS;
      const scenario = args.scenario_id
        ? scenarios.find(s => s.id === args.scenario_id)
        : scenarios[Math.floor(Math.random() * scenarios.length)];

      if (!scenario) {
        return { content: [{ type: "text", text: `Scenario not found: ${args.scenario_id}` }], isError: true };
      }

      // Build the exact requested scenario instead of delegating to the V1 generator,
      // which only samples from the full pool and can preview a different scenario.
      const entry = buildConversationV2(
        scenario,
        new SeededRNG(Date.now()),
        {
          count: 1,
          outputDir: path.join(os.tmpdir(), "pentesterflow-preview"),
          thinkingRatio: args.include_thinking ? 1.0 : 0.0,
          failureRatio: 0.35,
          minTurns: 8,
          maxTurns: 15,
          maxTokensPerEntry: 0,
          thinkingStyle: "inline",
        },
        0
      );
      const content = JSON.stringify(entry, null, 2);

      return {
        content: [{
          type: "text",
          text: `Preview: ${scenario.title}\nCategory: ${scenario.category} / ${scenario.subcategory}\nDifficulty: ${scenario.difficulty}\n\n${JSON.stringify(entry, null, 2).slice(0, 8000)}${content.length > 8000 ? "\n\n... (truncated for preview)" : ""}`,
        }],
      };
    }
  );
}
