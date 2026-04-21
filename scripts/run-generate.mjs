import { generateDatasetV2 } from "../dist/generators/v2/index.js";

const count = Number(process.env.COUNT || 2000);
const outputDir = process.env.OUTPUT_DIR || "./datasets";
const seed = process.env.SEED ? Number(process.env.SEED) : undefined;

console.error(`[run-generate] count=${count} outputDir=${outputDir} seed=${seed ?? "time-based"}`);

const start = Date.now();
const result = await generateDatasetV2({
  count,
  outputDir,
  thinkingRatio: 0.6,
  failureRatio: 0.35,
  minTurns: 8,
  maxTurns: 15,
  thinkingStyle: "inline",
  seed,
});
const elapsed = ((Date.now() - start) / 1000).toFixed(1);

console.error(`[run-generate] done in ${elapsed}s`);
console.error(JSON.stringify(
  {
    outputPath: result.outputPath,
    count: result.count,
    quality: result.qualityReport,
  },
  null,
  2
));
