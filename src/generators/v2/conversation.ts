// Conversation builder for Dataset Generator V2

import { ScenarioTemplate, AttackPhase } from "../../templates/scenarios/index.js";
import { PENTESTING_TOOLS, ToolDefinition } from "../../schemas/tools/index.js";
import { DynamicOutputEngine, SeededRNG, TargetProfile, generateTargetProfile } from "../outputs/index.js";
import { ThinkingEngine } from "../thinking-engine.js";

import { ShareGPTConversation, ShareGPTMessage, ToolCall, ToolResult, GenerationConfig } from "./types.js";
import {
  USER_PROMPTS_INITIAL,
  USER_PROMPTS_VULN_TESTING,
  USER_PROMPTS_EXPLOIT,
  USER_PROMPTS_FAILURE_FOLLOWUP,
  USER_PROMPTS_REPORT,
  USER_PROMPTS_DEEP_ANALYSIS,
  USER_PROMPTS_EVASION,
  DOMAINS,
} from "./prompts.js";
import { generateSystemPrompt } from "./system-prompts.js";
import { variateText, generateGroundedResponse, generateIntentResponse, classifyFailure } from "./responses.js";
import { generateUniqueReport, generateDeepAnalysis } from "./reports.js";
import { postProcessForQwen } from "./post-processor.js";
import { estimateTokens } from "./post-processor.js";

export function countTurns(messages: ShareGPTMessage[]): number {
  return messages.filter(m => m.from === "human" || m.from === "gpt").length;
}

export function identifyToolFromCommand(cmd: string): string | undefined {
  const toolKeywords: Record<string, string[]> = {
    nmap: ["nmap "],
    sqlmap: ["sqlmap "],
    ffuf: ["ffuf "],
    gobuster: ["gobuster "],
    nuclei: ["nuclei "],
    nikto: ["nikto "],
    wfuzz: ["wfuzz "],
    curl: ["curl "],
    httpx: ["httpx ", "| httpx"],
    subfinder: ["subfinder "],
    amass: ["amass "],
    dirsearch: ["dirsearch "],
    dalfox: ["dalfox "],
    commix: ["commix "],
    ssrfmap: ["ssrfmap "],
    jwt_tool: ["jwt_tool "],
    hydra: ["hydra "],
    metasploit: ["msfconsole", "metasploit"],
    arjun: ["arjun "],
    paramspider: ["paramspider "],
    gau: ["gau "],
    linpeas: ["linpeas"],
    feroxbuster: ["feroxbuster "],
    rustscan: ["rustscan "],
    trufflehog: ["trufflehog "],
    semgrep: ["semgrep "],
    katana: ["katana "],
    caido: ["caido "],
    puredns: ["puredns "],
    dnsx: ["dnsx "],
    interactsh: ["interactsh"],
    crlfuzz: ["crlfuzz "],
    corsy: ["corsy "],
    kiterunner: ["kr ", "kiterunner "],
    secretfinder: ["secretfinder "],
    linkfinder: ["linkfinder "],
    gf: ["gf "],
    testssl: ["testssl "],
    nosqlmap: ["nosqlmap "],
  };

  for (const [tool, keywords] of Object.entries(toolKeywords)) {
    if (keywords.some(kw => cmd.includes(kw))) return tool;
  }

  if (cmd.startsWith("python3") || cmd.startsWith("python ")) return "python_script";
  if (cmd.includes("for ") && cmd.includes("do ")) return "bash_script";
  if (cmd.startsWith("export ") || cmd.startsWith("aws ")) return "aws_cli";
  if (cmd.startsWith("kubectl ") || cmd.startsWith("k ")) return "kubectl";
  if (cmd.startsWith("docker ")) return "docker";
  if (cmd.startsWith("terraform ")) return "terraform";
  if (cmd.startsWith("gcloud ")) return "gcloud";
  if (cmd.startsWith("az ")) return "az_cli";

  return undefined;
}

export function generateDynamicOutput(
  engine: DynamicOutputEngine,
  toolName: string,
  domain: string,
  profile: TargetProfile,
  phase: AttackPhase,
  rng: SeededRNG
): string {
  switch (toolName) {
    case "nmap": return engine.generateNmapOutput(domain, profile);
    case "ffuf": return engine.generateFfufOutput(domain, profile);
    case "gobuster": return engine.generateGobusterOutput(domain, profile);
    case "sqlmap":
      if (phase.phase.toLowerCase().includes("detect") || phase.phase.toLowerCase().includes("discover")) return engine.generateSqlmapOutput(domain, profile, "detect");
      if (phase.phase.toLowerCase().includes("enum")) return engine.generateSqlmapOutput(domain, profile, "enumerate");
      if (phase.phase.toLowerCase().includes("dump") || phase.phase.toLowerCase().includes("extract")) return engine.generateSqlmapOutput(domain, profile, "dump");
      return engine.generateSqlmapOutput(domain, profile, rng.pick(["detect", "enumerate", "dump", "os"]));
    case "nuclei": return engine.generateNucleiOutput(domain, profile);
    case "curl": return engine.generateHttpResponse(profile, domain, rng.pick(["api_json", "error", "auth", "admin", "ssrf"]));
    case "httpx": return engine.generateHttpxOutput(domain, profile);
    case "subfinder": return engine.generateSubfinderOutput(domain, profile);
    case "amass": return engine.generateAmassOutput(domain, profile);
    case "jwt_tool": return engine.generateJwtOutput(rng.pick(["decode", "crack", "attack"]));
    case "dalfox": return engine.generateDalfoxOutput(domain, profile);
    case "nikto": return engine.generateNiktoOutput(domain, profile);
    case "wfuzz": return engine.generateWfuzzOutput(domain, profile);
    case "ssrfmap": return engine.generateHttpResponse(profile, domain, "ssrf");
    case "feroxbuster": return engine.generateFeroxbusterOutput(domain, profile);
    case "rustscan": return engine.generateRustscanOutput(domain, profile);
    case "trufflehog": return engine.generateTrufflehogOutput(domain, profile);
    case "semgrep": return engine.generateSemgrepOutput(domain, profile);
    case "katana": return engine.generateKatanaOutput(domain, profile);
    case "testssl": return engine.generateTestsslOutput(domain, profile);
    case "nosqlmap": return engine.generateNosqlmapOutput(domain, profile);
    case "metasploit": return engine.generateMetasploitOutput(domain, profile);
    case "crlfuzz": return `[VULN] Found CRLF injection at https://${rng.pick(profile.subdomains)}.${domain}/${rng.pick(profile.directories)} via ${rng.pick(["Header injection", "Response splitting", "Log injection"])}`;
    case "corsy": return `[VULN] ${domain} reflects arbitrary Origin header\n  Access-Control-Allow-Origin: https://evil.com\n  Access-Control-Allow-Credentials: true`;
    case "kiterunner": return `[${rng.int(200, 403)}] ${rng.pick(["GET", "POST", "PUT"])} https://${domain}/${rng.pick(["api/v1", "api/v2", "api/internal"])}/${rng.pick(["users", "admin", "config", "health", "debug", "metrics"])} [${rng.int(100, 9000)} bytes]`;
    case "secretfinder": return `[!] Found ${rng.int(1, 8)} secrets in JS files:\n  [API_KEY] https://${domain}/assets/app.js:${rng.int(100, 5000)} → ${engine.generateHex(32)}\n  [JWT] https://${domain}/assets/main.js:${rng.int(100, 3000)} → eyJhbGci...`;
    case "linkfinder": return Array.from({ length: rng.int(5, 15) }, () => `https://${domain}/${rng.pick(["api/v1", "api/v2", "internal"])}/${rng.pick(["users", "settings", "config", "auth", "data", "export", "graphql", "webhook"])}`).join("\n");
    case "dnsx": return Array.from({ length: rng.int(3, 10) }, () => `${rng.pick(profile.subdomains)}.${domain} [A] ${rng.pick([10, 172, 52, 34, 104])}.${rng.int(0, 255)}.${rng.int(0, 255)}.${rng.int(1, 254)}`).join("\n");
    case "puredns": return `Resolved ${rng.int(50, 500)} subdomains from ${rng.int(5000, 50000)} total\n${rng.pickN(profile.subdomains, rng.int(5, 15)).map(s => `${s}.${domain}`).join("\n")}`;
    case "arjun": {
      const stability = rng.pick(["stable", "unstable (high jitter)", "stable with minor variance"]);
      const anomalies = rng.int(0, 3);
      const paramCount = rng.int(2, 8);
      const foundParams = rng.pickN([...profile.injectableParams, "debug", "verbose", "admin", "token", "api_key", "format", "callback", "limit", "offset", "fields", "include", "expand", "v", "version", "lang"], paramCount);
      return `[*] Probing the target for stability\n[*] Target is ${stability}\n[*] Analysing HTTP response for anomalies\n[*] Found ${anomalies} anomalies in response\n[*] Performing parameter discovery (${rng.pick(["GET", "POST", "JSON"])} method)\n[*] Tried ${rng.int(2000, 10000)} payloads\n[+] Parameters found (${foundParams.length}): ${foundParams.join(", ")}\n[*] Completed in ${rng.float(2, 45).toFixed(1)}s`;
    }
    case "paramspider": {
      const paths = rng.pickN(["search", "users", "data", "page", "api/v1/query", "api/v2/filter", "download", "export", "redirect", "callback", "profile", "settings", "upload", "preview", "render"], rng.int(5, 12));
      return paths.map(p => `https://${rng.pick(profile.subdomains)}.${domain}/${p}?${rng.pick(profile.injectableParams)}=FUZZ`).join("\n");
    }
    case "gau": {
      const gauPaths = rng.pickN(["api/v1", "api/v2", "api/v3", "search", "page", "data", "admin", "login", "dashboard", "export", "download", "user", "settings", "graphql", "webhook", "callback", "reset-password", "verify"], rng.int(6, 15));
      return gauPaths.map(p => `https://${rng.pick(profile.subdomains)}.${domain}/${p}?${rng.pick(profile.injectableParams)}=${rng.pick(["test", "1", "admin", "true", "SELECT", "../etc/passwd", "http://localhost", "{{7*7}}", "<script>"])}`).join("\n");
    }
    case "hydra":
      return `Hydra v${rng.pick(["9.4", "9.5", "9.6"])} (c) 2024 by van Hauser/THC\n[DATA] max ${rng.int(4, 32)} tasks per 1 server, overall ${rng.int(4, 64)} tasks\n[DATA] attacking ${rng.pick(["http-post-form", "ssh", "ftp", "mysql", "http-get"])}://${domain}\n[${rng.pick(["80", "443", "22", "3306"])}][${rng.pick(["http-post-form", "ssh", "ftp", "mysql"])}] host: ${domain}   login: ${rng.pick(["admin", "root", "test", "user"])}   password: ${rng.pick(["admin123", "password", "P@ssw0rd!", "changeme", "letmein", "123456"])}\n1 of 1 target successfully completed, 1 valid password found`;
    case "commix":
      return `[info] Testing connection to the target URL.\n[info] Performing ${rng.pick(["classic", "eval-based", "time-based"])} injection technique.\n[info] The ${rng.pick(["GET", "POST"])} parameter '${rng.pick(profile.injectableParams)}' seems injectable via ${rng.pick(["classic", "eval-based", "time-based"])} injection technique.\n    Payload: ${rng.pick([";id", "| id", "$(id)", "`id`"])}\n[info] The target is vulnerable.\n    uid=${rng.int(33, 1000)}(${rng.pick(["www-data", "apache", "nginx", "node", "app"])}) gid=${rng.int(33, 1000)}(${rng.pick(["www-data", "apache", "nginx", "nogroup"])})`;
    case "linpeas":
      return `${rng.pick(["╔══════════╣", "════════════"])} ${rng.pick(["SUID binaries", "Writable files", "Interesting GROUPs", "Cron jobs", "Docker membership", "Kernel version"])}\n${rng.pick(["/usr/bin/pkexec\n/usr/bin/sudo\n/usr/local/bin/" + rng.pick(["backup", "deploy", "monitor"]) + " (Unknown SUID!)", "/etc/crontab writable\n/opt/scripts/" + rng.pick(["backup.sh", "deploy.sh", "cleanup.sh"]) + " writable", "uid=" + rng.int(33, 1000) + "(" + rng.pick(["www-data", "app"]) + ") groups=" + rng.pick(["docker", "sudo", "lxd", "adm"])])}\n\n${rng.pick(["╔══════════╣", "════════════"])} ${rng.pick(["Kernel", "OS Info"])}\nLinux ${rng.pick(["5.4.0", "5.15.0", "6.1.0", "5.10.0"])}-${rng.int(50, 200)}-${rng.pick(["generic", "amd64", "cloud"])} #${rng.int(50, 250)}\n${rng.pick(["Ubuntu 22.04", "Ubuntu 20.04", "Debian 12", "CentOS 8", "Amazon Linux 2"])}`;
    default: {
      // Dynamic fallback for scripts/custom tools — NEVER use static template text
      const sub = rng.pick(profile.subdomains);
      const user = engine.generateRandomUser();
      const customOutputs = [
        `[+] Script completed successfully\n[+] Target: ${sub}.${domain}\n[+] Found ${rng.int(1, 50)} results\n[+] Data saved to /tmp/output_${engine.generateHex(6)}.json\n\nSample output:\n${JSON.stringify({ id: rng.int(1, 9999), email: user.email, role: user.role }, null, 2)}`,
        `$ python3 exploit.py --target https://${sub}.${domain} --param ${rng.pick(profile.injectableParams)}\n[*] Connecting to target...\n[*] Sending ${rng.int(1, 100)} requests...\n[+] ${rng.pick(["Vulnerability confirmed", "Data extracted", "Access granted", "Bypass successful", "Shell obtained"])}\n[+] Response: ${rng.int(200, 500)} (${rng.int(100, 9000)} bytes)\n[+] Extracted ${rng.int(1, 500)} records`,
        `#!/bin/bash\n# Results from automated scan of ${domain}\nTARGETS_SCANNED=${rng.int(5, 50)}\nVULNERABLE=${rng.int(1, 10)}\nCRITICAL=${rng.int(0, 3)}\n\n[+] ${sub}.${domain} - ${rng.pick(["VULNERABLE", "INTERESTING", "NEEDS_REVIEW"])}\n[+] Port ${rng.pick(profile.openPorts)} - ${rng.pick(["open", "filtered"])}\n[+] Parameter ${rng.pick(profile.injectableParams)} - ${rng.pick(["injectable", "reflected", "stored"])}\n[+] Duration: ${rng.int(1, 300)}s`,
      ];
      return rng.pick(customOutputs);
    }
  }
}

export function buildConversationV2(
  scenario: ScenarioTemplate,
  rng: SeededRNG,
  config: GenerationConfig,
  entryIndex: number
): ShareGPTConversation {
  const domain = rng.pick(DOMAINS);
  const profile = generateTargetProfile(rng);
  profile.domain = domain;

  const outputEngine = new DynamicOutputEngine(rng.int(0, 999999999));
  const thinkingEngine = new ThinkingEngine(rng.int(0, 999999999));

  const includeThinking = rng.bool(config.thinkingRatio);
  const includeFailures = rng.bool(config.failureRatio);
  // FIX #19: Triage slice. ~18% of entries are quick triage conversations —
  // 1–2 phases, a brief finding summary instead of a formal CVSS/remediation
  // report. Teaches the model that not every pentest task ends in a full
  // report, so it doesn't always steer toward report mode.
  const isTriage = rng.bool(0.18);

  const messages: ShareGPTMessage[] = [];
  const toolsUsed: string[] = [];
  let hasFailures = false;

  // FIX #5: Single shorter system message (combine role + tools, save tokens)
  const scenarioTools = scenario.tools_involved
    .map(name => PENTESTING_TOOLS.find(t => t.name === name))
    .filter((t): t is ToolDefinition => t !== undefined);
  const extraTools = rng.pickN(
    PENTESTING_TOOLS.filter(t => !scenario.tools_involved.includes(t.name)),
    rng.int(1, 3)
  );
  const allTools = [...scenarioTools, ...extraTools];
  const toolsList = allTools.map(t => `- ${t.name}: ${t.description.slice(0, 80)}`).join('\n');

  messages.push({
    from: "system",
    value: `${generateSystemPrompt(rng, profile)}\n\nAvailable tools:\n${toolsList}`,
  });

  // 3. Initial user prompt (highly varied)
  const targetDesc = variateText(scenario.target_description, domain, profile);
  const techStr = `${profile.technologies.join("/")} with ${profile.databases.name} database`;

  const triagePrompts = [
    `Quick triage on ${domain} — is the ${scenario.subcategory.toLowerCase()} issue worth a deeper look, or can we rule it out fast?`,
    `Can you do a fast check on ${domain} for ${scenario.subcategory.toLowerCase()}? Just want a go/no-go before I book time for full testing.`,
    `Give me a quick read on whether ${domain} has a ${scenario.subcategory.toLowerCase()} exposure. Short answer is fine.`,
    `I only have ~10 minutes — confirm or reject the ${scenario.subcategory.toLowerCase()} hypothesis on ${domain}.`,
    `Fast triage: does ${domain} look exposed to ${scenario.subcategory.toLowerCase()}? No full report needed, just the call.`,
  ];
  const initialPrompt = isTriage
    ? rng.pick(triagePrompts) + `\n\nTarget context: ${targetDesc}`
    : rng.pick(USER_PROMPTS_INITIAL).replace(/\{domain\}/g, domain)
        + `\n\nTarget context: ${targetDesc}\nTechnology: ${techStr}`;

  messages.push({ from: "human", value: initialPrompt });

  // FIX #1: Randomize phase order — sometimes skip phases, sometimes reorder
  let phases = [...scenario.attack_phases];
  if (isTriage) {
    // Triage conversations only cover 1–2 phases — the analyst is doing a
    // quick check, not a full chain. Picks the most diagnostic phase (usually
    // the first or the detection phase) plus optionally one more.
    const phaseCount = rng.pick([1, 1, 2]);
    phases = phases.slice(0, phaseCount);
  } else {
    const structureVariant = rng.int(0, 4);
    if (structureVariant === 1 && phases.length > 3) {
      // Skip one middle phase
      const skipIdx = rng.int(1, phases.length - 2);
      phases = phases.filter((_, i) => i !== skipIdx);
    } else if (structureVariant === 2 && phases.length > 2) {
      // Merge first two phases into one
      phases = [phases[0], ...phases.slice(2)];
    }
  }
  // structureVariant 0, 3, 4 = normal order (60% of entries)

  // FIX #3: Decide WHERE failures happen (not always middle)
  const failurePhaseIdx = includeFailures ? rng.int(0, phases.length - 1) : -1;
  // Also: 15% chance of "nothing found" even in non-failure entries
  const softFailChance = 0.15;

  // Track tool outputs for grounding
  let lastToolOutputSummary = "";
  let lastFindingSummary = "";
  // Per-entry curl budget — suppress runaway curl usage. Scenario templates are
  // heavily curl-biased; capping per entry is the only way to break the 88%+
  // curl-occurrence rate without rewriting every scenario file.
  // Distribution: ~50% of entries get zero curl, ~33% get one, ~17% get two.
  let curlCallsRemaining = rng.pick([0, 0, 0, 1, 1, 2]);

  // 4. Phase-by-phase conversation generation
  for (let phaseIdx = 0; phaseIdx < phases.length; phaseIdx++) {
    const phase = phases[phaseIdx];
    const isFailurePhase = phaseIdx === failurePhaseIdx;
    const isSoftFail = !isFailurePhase && rng.bool(softFailChance);

    // FIX #1: Sometimes do multiple tool calls then one analysis, sometimes interleave
    const toolCalls: ToolCall[] = [];
    const toolResults: ToolResult[] = [];
    const toolOutputTexts: string[] = []; // FIX #7: collect for grounding

    // FIX #9: Vary command construction — don't always use template commands
    const cmdCount = rng.int(1, Math.min(phase.commands.length, rng.int(2, 5)));
    const cleanCmds = phase.commands.filter(c => !c.startsWith("#") && c.trim() !== "");
    // FIX #10: Bias selection toward commands whose primary tool hasn't been used yet
    // in this entry, so tool coverage spreads across scenario.tools_involved.
    // Also enforce per-entry curl budget — when it's exhausted, drop curl commands
    // from the candidate pool entirely.
    const usedSet = new Set(toolsUsed);
    const dropCurl = curlCallsRemaining <= 0;
    // FIX #16b: Curl-budget exhausted → rewrite curl commands. Instead of
    // defaulting to httpx/python_script (which just shifts the monoculture),
    // route each rewrite to a scenario-appropriate native tool based on the
    // URL shape, request method, and scenario tags. Falls back to httpx only
    // when nothing else fits.
    const rewriteCurl = (c: string): string => {
      if (!c.includes("curl")) return c;
      const urlMatch = c.match(/https?:\/\/\S+/);
      const url = urlMatch ? urlMatch[0].replace(/['"`,;]/g, "") : `https://${domain}/`;
      const method = /-X\s+(POST|PUT|DELETE|PATCH)/i.test(c) ? (c.match(/-X\s+(POST|PUT|DELETE|PATCH)/i) as RegExpMatchArray)[1].toUpperCase() : "GET";
      const headers = [...c.matchAll(/-H\s+['"]([^'"]+)['"]/g)].map(m => m[1]);
      const body = c.match(/-d\s+['"]([^'"]+)['"]/)?.[1];

      // Scenario-appropriate rewrite targets. Order matters: most specific first.
      const candidates: Array<{ tool: string; command: string; fitness: number }> = [];

      const tags = new Set(scenario.tags.map(t => t.toLowerCase()));
      const toolsPool = new Set(scenario.tools_involved);

      // SQLi scenarios: route to sqlmap if it's in scope, regardless of method.
      if ((tags.has("sqli") || tags.has("injection") || tags.has("nosql")) && toolsPool.has("sqlmap")) {
        candidates.push({ tool: "sqlmap", command: `sqlmap -u "${url}" --batch --level=3 --risk=2 --random-agent`, fitness: 9 });
      }
      if (tags.has("nosql") && toolsPool.has("nosqlmap")) {
        candidates.push({ tool: "nosqlmap", command: `nosqlmap -u ${url} --batch`, fitness: 9 });
      }
      // JWT scenarios: jwt_tool decode/inspect
      if ((tags.has("jwt") || tags.has("auth-bypass") || /Authorization:.*Bearer/i.test(headers.join(" "))) && toolsPool.has("jwt_tool")) {
        const tokenMatch = headers.join(" ").match(/Bearer\s+([A-Za-z0-9._-]+)/);
        const tok = tokenMatch ? tokenMatch[1] : "$TOKEN";
        candidates.push({ tool: "jwt_tool", command: `jwt_tool ${tok} -T`, fitness: 8 });
      }
      // XSS scenarios: dalfox scan
      if (tags.has("xss") && toolsPool.has("dalfox")) {
        candidates.push({ tool: "dalfox", command: `dalfox url ${url}`, fitness: 8 });
      }
      // Dir/endpoint discovery: ffuf / feroxbuster
      if (/FUZZ|\/api\/|\/v1\/|\/v2\/|fuzz/i.test(c)) {
        if (toolsPool.has("ffuf")) candidates.push({ tool: "ffuf", command: `ffuf -u ${url.replace(/FUZZ/g, "") || url}/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -mc 200,301,302,403`, fitness: 7 });
        if (toolsPool.has("feroxbuster")) candidates.push({ tool: "feroxbuster", command: `feroxbuster -u ${url} -t 50 --silent`, fitness: 6 });
      }
      // Vuln probe endpoints: nuclei
      if (tags.has("ssrf") || tags.has("xxe") || tags.has("ssti") || tags.has("rce") || toolsPool.has("nuclei")) {
        candidates.push({ tool: "nuclei", command: `nuclei -u ${url} -severity medium,high,critical -silent`, fitness: 6 });
      }
      // Arg discovery: arjun
      if (tags.has("idor") || tags.has("mass-assignment") || /\?[a-z_]+=/i.test(url)) {
        if (toolsPool.has("arjun")) candidates.push({ tool: "arjun", command: `arjun -u ${url} -m ${method}`, fitness: 5 });
      }
      // LDAP / 2FA / race: python script is genuinely the right tool.
      if (tags.has("race-condition") || tags.has("2fa-bypass") || tags.has("logic")) {
        const headerDict = headers.length ? `, headers={${headers.map(h => { const [k, ...v] = h.split(":"); return `'${k.trim()}': '${v.join(":").trim()}'`; }).join(", ")}}` : "";
        const bodyArg = body ? `, data=${JSON.stringify(body)}` : "";
        candidates.push({ tool: "python_script", command: `python3 -c "import requests; r = requests.request('${method}', '${url}'${headerDict}${bodyArg}, timeout=15); print(r.status_code, r.headers.get('content-type','')); print(r.text[:2000])"`, fitness: 5 });
      }
      // Generic GET fallback: httpx is the honest default for "fetch and inspect".
      if (method === "GET") {
        const hdr = headers[0] ? ` -H '${headers[0]}'` : "";
        candidates.push({ tool: "httpx", command: `httpx -u ${url} -status-code -title -tech-detect -follow-redirects${hdr}`, fitness: 3 });
      }
      // Last-resort python for POST/PUT when nothing scenario-specific fits.
      if (candidates.length === 0 || method !== "GET") {
        const headerDict = headers.length ? `, headers={${headers.map(h => { const [k, ...v] = h.split(":"); return `'${k.trim()}': '${v.join(":").trim()}'`; }).join(", ")}}` : "";
        const bodyArg = body ? `, data=${JSON.stringify(body)}` : "";
        candidates.push({ tool: "python_script", command: `python3 -c "import requests; r = requests.request('${method}', '${url}'${headerDict}${bodyArg}, timeout=15); print(r.status_code, r.headers.get('content-type','')); print(r.text[:2000])"`, fitness: 2 });
      }

      // Penalize tools already heavily used this entry to spread distribution.
      const usageCounts = toolsUsed.reduce((acc: Record<string, number>, t) => { acc[t] = (acc[t] || 0) + 1; return acc; }, {});
      const scored = candidates.map(c => ({ ...c, score: c.fitness - (usageCounts[c.tool] || 0) * 2 }));
      scored.sort((a, b) => b.score - a.score);
      // Top-fitness candidates with some randomness to avoid deterministic rewrites.
      const topTier = scored.filter(s => s.score >= scored[0].score - 2);
      return rng.pick(topTier).command;
    };
    const candidatePool = dropCurl
      ? cleanCmds.map(c => identifyToolFromCommand(c) === "curl" ? rewriteCurl(c) : c)
      : cleanCmds;
    const freshCmds = candidatePool.filter(c => {
      const t = identifyToolFromCommand(c);
      return t && !usedSet.has(t) && t !== "curl";
    });
    const staleCmds = candidatePool.filter(c => !freshCmds.includes(c));
    let selectedCmds: string[];
    if (candidatePool.length === 0) {
      // Every command this phase was curl and budget is spent. Skip the whole
      // phase — no tool calls, no synthetic analysis — to avoid emitting
      // "analysis without evidence" turns that hurt tool-use training.
      continue;
    } else if (freshCmds.length >= cmdCount) {
      selectedCmds = rng.pickN(freshCmds, cmdCount);
    } else if (freshCmds.length > 0) {
      selectedCmds = [
        ...rng.pickN(freshCmds, freshCmds.length),
        ...rng.pickN(staleCmds, cmdCount - freshCmds.length),
      ];
    } else {
      selectedCmds = rng.pickN(candidatePool, cmdCount);
    }

    for (let cmdIdx = 0; cmdIdx < selectedCmds.length; cmdIdx++) {
      let cmd = variateText(selectedCmds[cmdIdx], domain, profile);
      // FIX #9: Add random flags/variations to commands
      if (rng.bool(0.3) && cmd.includes("curl")) {
        cmd += rng.pick([" --connect-timeout 10", " -w '\\n%{http_code}'", " --max-time 30", ` -H 'X-Request-Id: ${outputEngine.generateUUID()}'`]);
      }
      if (rng.bool(0.2) && cmd.includes("ffuf")) {
        cmd += rng.pick([" -rate 100", " -timeout 15", " -ac", ` -H 'User-Agent: Mozilla/5.0'`]);
      }

      const toolCallId = `call_${entryIndex}_${phaseIdx}_${cmdIdx}_${rng.int(10000, 99999)}`;
      const toolName = identifyToolFromCommand(cmd);
      if (toolName) {
        toolsUsed.push(toolName);
        if (toolName === "curl") curlCallsRemaining--;
      }

      toolCalls.push({
        id: toolCallId,
        name: toolName || "bash",
        arguments: { command: cmd },
      });

      let output: string;
      if (isFailurePhase) {
        output = outputEngine.generateFailureOutput(toolName || "generic", cmd);
        hasFailures = true;
      } else if (isSoftFail && cmdIdx === 0) {
        // FIX #3: Soft failure — tool runs but finds nothing interesting
        output = outputEngine.generateFailureOutput(toolName || "generic", cmd);
      } else {
        output = generateDynamicOutput(outputEngine, toolName || "bash", domain, profile, phase, rng);
      }

      toolOutputTexts.push(output.slice(0, 200)); // FIX #7: save summary for grounding
      toolResults.push({ tool_call_id: toolCallId, name: toolName || "bash", output });
    }

    // FIX #7: Build grounding context from tool outputs
    lastToolOutputSummary = toolOutputTexts.join(" | ").slice(0, 300);

    // FIX #15: observation-aware thinking. Classify the actual tool output
    // first and let the classification (not just phase metadata) drive which
    // thinking generator runs. If the observation shows a hard failure
    // (Connection refused, 429, WAF block, timeout), force failure-thinking
    // so the reasoning can't claim "no injectable parameters found" when the
    // real problem was that the host was unreachable.
    const obsFailClass = lastToolOutputSummary ? classifyFailure(lastToolOutputSummary) : "generic";
    const obsSaysHardFailure = obsFailClass !== "generic";
    const realIsFailure = isFailurePhase || isSoftFail || obsSaysHardFailure;

    let thinkingBlock: string | undefined;
    if (includeThinking) {
      if (realIsFailure) {
        const why = ({
          unreachable: "the target was unreachable — connection refused or the host is offline, so no application-layer signal was produced",
          ratelimited: "rate limiting kicked in and cut the test short — the result is inconclusive, not safe",
          blocked: "the WAF / input filter intercepted the payloads before they reached the application logic",
          timeout: "the request timed out — no response came back, so no vulnerability signal either way",
          generic: rng.pick([
            "no exploitable behavior was detected for this specific technique",
            "input validation appears to handle this payload class correctly",
            "the endpoint returned consistent responses across payload variations",
          ]),
        } as Record<string, string>)[obsFailClass] || "no exploitable signal was observed";
        thinkingBlock = thinkingEngine.generateFailureThinking(domain, profile, phase.phase, why);
      } else {
        // Feed the actual observation summary as evidence so reasoning is
        // grounded in what the tool returned, not just phase.analysis.
        const evidence = lastToolOutputSummary && lastToolOutputSummary.length > 30
          ? lastToolOutputSummary
          : phase.analysis;
        if (phaseIdx === 0) {
          thinkingBlock = thinkingEngine.generateReconThinking(domain, profile, [evidence]);
        } else if (phase.phase.toLowerCase().includes("enum") || phase.phase.toLowerCase().includes("discover")) {
          thinkingBlock = thinkingEngine.generateEnumThinking(domain, profile, phase.phase);
        } else if (phase.phase.toLowerCase().includes("exploit") || phase.phase.toLowerCase().includes("attack")) {
          thinkingBlock = thinkingEngine.generateExploitThinking(domain, profile, scenario.subcategory, evidence);
        } else {
          thinkingBlock = thinkingEngine.generateVulnAnalysisThinking(domain, profile, scenario.subcategory, evidence);
        }
      }
    }

    // FIX #11 (causal tool-use) + FIX #12 (thinking placement):
    //   Pre-call thinking blocks were outcome-oriented (they came from helpers
    //   that assume a finding already exists). When attached to the intent
    //   turn, they leak results before the tool runs. The fix is to attach
    //   thinking ONLY to the post-observation analysis turn — by then the
    //   tool output exists and reasoning about it is causally valid.
    //
    //   Intent narration also now uses the actual tool names from the
    //   selected tool_calls instead of phase.tools, so the narration can't
    //   name a different tool than the one actually invoked.
    if (toolCalls.length > 0) {
      const actualToolNames = toolCalls.map(tc => tc.name);
      const intent = generateIntentResponse(rng, phase, profile, domain, actualToolNames);
      messages.push({
        from: "gpt",
        value: intent,
        tool_calls: toolCalls,
        // no thinking here — tool hasn't run yet
      });
      messages.push({
        from: "tool",
        value: toolResults.map(r => `[${r.name}] Output:\n${r.output}`).join("\n\n---\n\n"),
        tool_results: toolResults,
      });
      // Use realIsFailure — derived from the actual observation — not just
      // the phase-level flag, so visible analysis and failure note match
      // what the tool really returned.
      const grounded = generateGroundedResponse(rng, phase, profile, domain, realIsFailure, lastToolOutputSummary, includeThinking, actualToolNames);
      lastFindingSummary = grounded.slice(0, 150);
      messages.push({
        from: "gpt",
        value: grounded,
        thinking: thinkingBlock,
      });
    } else {
      // No tool calls this phase (curl-only phase with empty budget). Single
      // analysis turn; thinking is fine here since no tool output is being
      // pre-empted.
      const grounded = generateGroundedResponse(rng, phase, profile, domain, realIsFailure, lastToolOutputSummary, includeThinking, []);
      lastFindingSummary = grounded.slice(0, 150);
      messages.push({
        from: "gpt",
        value: grounded,
        thinking: thinkingBlock,
      });
    }

    // FIX #8: Contextual user follow-ups referencing prior findings
    if (phaseIdx < phases.length - 1) {
      const nextPhase = phases[phaseIdx + 1];
      let followUp: string;

      if (isFailurePhase || isSoftFail) {
        // 40% evasion-specific prompts, 60% general failure follow-ups
        followUp = rng.bool(0.4) ? rng.pick(USER_PROMPTS_EVASION) : rng.pick(USER_PROMPTS_FAILURE_FOLLOWUP);
      } else {
        // FIX #8: 60% contextual (reference prior findings), 40% generic
        if (rng.bool(0.6)) {
          const contextParts = [
            `Based on what you just found on ${rng.pick(profile.subdomains)}.${domain}`,
            `You mentioned the \`${rng.pick(profile.injectableParams)}\` parameter is ${rng.pick(["injectable", "reflected", "vulnerable", "interesting"])}`,
            `The ${rng.pick(profile.technologies)} backend seems to have ${rng.pick(["weak validation", "no authorization checks", "exposed debug info", "verbose errors"])}`,
            `Since we confirmed the ${scenario.subcategory} issue`,
            `The tool output showed ${rng.pick(["several open ports", "interesting directories", "database errors", "reflected input", "missing security headers"])}`,
            `Looking at the ${profile.databases.name} error from the last scan`,
          ];
          followUp = `${rng.pick(contextParts)} — ${rng.pick([
            `can you test if ${rng.pick(["other endpoints", "the admin panel", "the API v1", "the mobile API"])} has the same issue?`,
            `try to escalate this further. What's the worst-case impact?`,
            `chain this with the ${rng.pick(["authentication", "authorization", "session handling", "CORS config"])} to increase severity.`,
            `exploit it fully and extract evidence for the report.`,
            `check if the ${rng.pick(["WAF", "rate limiter", "input filter", "CSP"])} catches this attack pattern.`,
            `test the same parameter with ${rng.pick(["time-based payloads", "out-of-band techniques", "different encoding", "a custom script"])}.`,
          ])}`;
        } else if (nextPhase.phase.toLowerCase().includes("exploit")) {
          followUp = rng.pick(USER_PROMPTS_EXPLOIT)
            .replace(/\{endpoint\}/g, `https://${rng.pick(profile.subdomains)}.${domain}/${rng.pick(["api", "v1", "v2"])}/${rng.pick(["users", "search", "login", "profile"])}`)
            .replace(/\{vulnType\}/g, scenario.subcategory)
            .replace(/\{param\}/g, rng.pick(profile.injectableParams));
        } else if (nextPhase.phase.toLowerCase().includes("report")) {
          followUp = rng.pick(USER_PROMPTS_REPORT).replace(/\{vulnType\}/g, scenario.title);
        } else {
          followUp = rng.pick(USER_PROMPTS_VULN_TESTING)
            .replace(/\{endpoint\}/g, `https://${rng.pick(profile.subdomains)}.${domain}/${rng.pick(["api/v1", "api/v2", "api"])}/${rng.pick(["users", "search", "login", "profile"])}`)
            .replace(/\{param\}/g, rng.pick(profile.injectableParams));
        }
      }

      messages.push({ from: "human", value: followUp });
    }
  }

  // FIX #10b: Tool-spotlight pass — if scenario declares tools that never got called,
  // insert a dedicated turn that exercises one of them. Spreads tool coverage without
  // editing every scenario template.
  // Triage entries skip this — they're supposed to be short.
  const missingTools = scenario.tools_involved.filter(t => t !== "curl" && !toolsUsed.includes(t));
  if (!isTriage && missingTools.length > 0 && rng.bool(0.7)) {
    const spotlightTool = rng.pick(missingTools);
    const toolDef = PENTESTING_TOOLS.find(t => t.name === spotlightTool);
    const spotlightCmd = toolDef?.example_commands?.[0]
      ? variateText(toolDef.example_commands[0], domain, profile)
      : `${spotlightTool} ${domain}`;
    const callId = `call_${entryIndex}_spotlight_${rng.int(10000, 99999)}`;

    messages.push({
      from: "human",
      value: `Good. Now run a focused ${spotlightTool} pass against ${domain} — I want to cross-check with a different tool before we write this up.`,
    });

    const spotOutput = generateDynamicOutput(outputEngine, spotlightTool, domain, profile, scenario.attack_phases[0], rng);
    messages.push({
      from: "gpt",
      value: `Running ${spotlightTool} to corroborate the earlier findings.`,
      tool_calls: [{ id: callId, name: spotlightTool, arguments: { command: spotlightCmd } }],
    });
    messages.push({
      from: "tool",
      value: `[${spotlightTool}] Output:\n${spotOutput}`,
      tool_results: [{ tool_call_id: callId, name: spotlightTool, output: spotOutput }],
    });
    const priorTool = toolsUsed.length > 0 ? toolsUsed[toolsUsed.length - 1] : "the earlier scan";
    messages.push({
      from: "gpt",
      value: `${spotlightTool} confirms the earlier result — ${rng.pick([
        "same vulnerable surface, slightly different signature",
        `consistent with what ${priorTool} showed but with extra metadata`,
        "adds confidence that this isn't a false positive",
        "matches the pattern from the first phase",
      ])}. Ready for the report.`,
    });
    toolsUsed.push(spotlightTool);
  }

  // 5. Final turn — full report for normal entries, brief triage summary otherwise.
  //    Triage entries end with a short verdict, not a CVSS/remediation report,
  //    so the model sees that not every task ends in full report mode.
  if (isTriage) {
    const verdict = hasFailures
      ? rng.pick([
          `**Triage verdict:** no conclusive signal for ${scenario.subcategory.toLowerCase()} in the time I had. Not a confirmed rule-out — just nothing exploitable surfaced from this pass. Worth a deeper look if there's a specific reason to suspect it.`,
          `**Quick read:** I didn't find an exploitable ${scenario.subcategory.toLowerCase()} path in this window. Could be a true negative, could be defended, could need a richer payload set. Flag if you want me to go deeper.`,
        ])
      : rng.pick([
          `**Triage verdict:** ${scenario.subcategory.toLowerCase()} looks real on ${domain}. Not a full exploit write-up yet, but the signal is there. Worth booking proper testing time.`,
          `**Quick read:** I'd call this a likely ${scenario.subcategory.toLowerCase()} issue based on what I saw. Not a certified finding, but I'd prioritize it for the full engagement.`,
          `**Verdict:** high enough confidence to recommend a full pass on ${scenario.subcategory.toLowerCase()}. Short version: the endpoint behavior matches the pattern. Full report to follow when we have time.`,
        ]);
    messages.push({ from: "gpt", value: verdict });
  } else {
    messages.push({
      from: "human",
      value: rng.pick(USER_PROMPTS_REPORT).replace(/\{vulnType\}/g, scenario.title),
    });
    const reportThinking = includeThinking
      ? thinkingEngine.generateReportThinking(domain, scenario.subcategory, scenario.difficulty, scenario.attack_phases.map(p => p.phase))
      : undefined;
    messages.push({
      from: "gpt",
      value: generateUniqueReport(scenario, domain, profile, rng),
      thinking: reportThinking,
    });
  }

  // 6. Pad to a per-entry target turn count sampled uniformly in [minTurns, maxTurns].
  // Previously this only padded to minTurns, so 94% of entries had exactly minTurns turns.
  // Triage entries skip padding — they're supposed to be short (4–8 turns).
  const targetTurns = isTriage
    ? countTurns(messages) // no padding
    : rng.int(config.minTurns, Math.max(config.minTurns, config.maxTurns));
  while (countTurns(messages) < targetTurns) {
    // FIX #8: Contextual deep analysis prompts
    messages.push({
      from: "human",
      value: rng.pick(USER_PROMPTS_DEEP_ANALYSIS),
    });

    const addlThinking = includeThinking
      ? thinkingEngine.generatePostExploitThinking(domain, profile, rng.pick(["application-level", "database-level", "OS-level", "network-level"]))
      : undefined;

    messages.push({
      from: "gpt",
      value: generateDeepAnalysis(scenario, domain, profile, rng),
      thinking: addlThinking,
    });
  }

  // Post-process: apply Qwen-compatible transformations
  const finalMessages = postProcessForQwen(messages, config);

  return {
    id: `pentesterflow-${scenario.id}-${rng.int(100000, 999999)}-${entryIndex}`,
    conversations: finalMessages,
    metadata: {
      scenario_id: scenario.id,
      category: scenario.category,
      subcategory: scenario.subcategory,
      difficulty: scenario.difficulty,
      tags: scenario.tags,
      tools_used: [...new Set(toolsUsed)],
      has_thinking: includeThinking,
      has_failures: hasFailures,
      is_triage: isTriage,
      turn_count: countTurns(finalMessages),
      cve_references: scenario.cve_references || [],
      estimated_tokens: estimateTokens(finalMessages),
      generated_at: new Date().toISOString(),
    },
  };
}
