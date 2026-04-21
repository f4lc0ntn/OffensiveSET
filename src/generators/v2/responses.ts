// Response generation functions for Dataset Generator V2

import { SeededRNG, TargetProfile } from "../outputs/index.js";
import { AttackPhase } from "../../templates/scenarios/index.js";

// FIX #12: Comprehensive target.com replacement — catch ALL variants
export function variateText(text: string, domain: string, profile: TargetProfile): string {
  return text
    // Specific subdomains first (before generic target.com)
    .replace(/shop\.target\.com/g, `shop.${domain}`)
    .replace(/api\.target\.com/g, `api.${domain}`)
    .replace(/admin\.target\.com/g, `admin.${domain}`)
    .replace(/corp\.target\.com/g, `corp.${domain}`)
    .replace(/cloud-app\.target\.com/g, `cloud.${domain}`)
    .replace(/webapp\.target\.com/g, `app.${domain}`)
    .replace(/app\.target\.com/g, `app.${domain}`)
    .replace(/forum\.target\.com/g, `forum.${domain}`)
    .replace(/enterprise\.target\.com/g, `enterprise.${domain}`)
    .replace(/bank\.target\.com/g, `bank.${domain}`)
    .replace(/jobs\.target\.com/g, `jobs.${domain}`)
    .replace(/store\.target\.com/g, `store.${domain}`)
    .replace(/trade\.target\.com/g, `trade.${domain}`)
    .replace(/www\.target\.com/g, `www.${domain}`)
    .replace(/ws\.target\.com/g, `ws.${domain}`)
    .replace(/hr-api\.target\.com/g, `hr-api.${domain}`)
    .replace(/saas-api\.target\.com/g, `saas-api.${domain}`)
    .replace(/mobile-api\.target\.com/g, `mobile-api.${domain}`)
    .replace(/auth\.target\.com/g, `auth.${domain}`)
    // Generic catch-all LAST
    .replace(/[\w-]*\.?target\.com/g, domain)
    // IPs
    .replace(/10\.10\.10\.1/g, profile.ip)
    .replace(/10\.0\.1\.50/g, profile.ip)
    .replace(/192\.168\.1\.\d+/g, profile.ip)
    .replace(/192\.168\.100\.\d+/g, profile.ip)
    .replace(/172\.16\.0\.\d+/g, profile.ip)
    // Database names
    .replace(/PostgreSQL/g, profile.databases.name)
    .replace(/postgresql/g, profile.databases.name.toLowerCase());
}

// Classify a tool-output string into a coarse failure category so downstream
// narrative can match the actual observation instead of claiming a mismatched
// cause (e.g. rate limiting when the connection was refused).
export function classifyFailure(observation: string): "unreachable" | "ratelimited" | "blocked" | "timeout" | "generic" {
  const o = observation || "";
  if (/Connection refused|Failed to connect|Could not resolve|No route to host|Host unreachable|Name or service not known/i.test(o)) return "unreachable";
  if (/\b429\b|rate[- ]?limit|Too Many Requests|throttl/i.test(o)) return "ratelimited";
  if (/\b403\b|\b406\b|WAF|blocked by|denied by policy|cloudflare|akamai|imperva|mod_security/i.test(o)) return "blocked";
  if (/timed out|timeout|no response|operation timed/i.test(o)) return "timeout";
  return "generic";
}

// Pre-call intent response: what the assistant says BEFORE running a tool.
// Must not reference tool output — the tool hasn't run yet. Keeps it short and
// stateable so the subsequent tool_call reads as an action, not a conclusion.
export function generateIntentResponse(
  rng: SeededRNG,
  phase: AttackPhase,
  profile: TargetProfile,
  domain: string,
  actualTools?: string[]
): string {
  const tech = rng.pick(profile.technologies);
  // Prefer names of the tools actually being invoked this turn — otherwise the
  // intent narration can claim a tool the tool_call does not use.
  const toolPool = (actualTools && actualTools.length > 0) ? actualTools : (phase.tools || ["the next tool"]);
  const tool = rng.pick(toolPool);
  const verb = rng.pick([
    "Let me",
    "I'll",
    "Going to",
    "Next I'll",
    "My plan is to",
  ]);
  const goal = rng.pick([
    `run ${tool} against ${domain} to ${phase.description.toLowerCase()}`,
    `kick off ${phase.phase.toLowerCase()} with ${tool} — focus is ${phase.description.toLowerCase()}`,
    `use ${tool} for ${phase.phase.toLowerCase()}; I want to see how the ${tech} stack responds`,
    `probe ${domain} with ${tool} and look for ${rng.pick([
      "anomalous responses",
      "exposed endpoints",
      "version banners",
      "parameter reflection",
      "auth misconfigurations",
    ])}`,
    `execute the ${phase.phase.toLowerCase()} step. ${tool} is the right choice here because ${rng.pick([
      "it handles this surface efficiently",
      "it gives me the signal I need without noise",
      "it matches the target's stack",
      "it's the standard tool for this phase",
    ])}`,
  ]);
  return `${verb} ${goal}.`;
}

// FIX #2 + #4 + #7 + #14: Grounded Response Generator
// - Varies format (no always-## headers)
// - Grounds analysis in tool output data
// - Longer responses when thinking is present
// - Analysis narration names the tool(s) that actually ran (actualTools),
//   not the scenario-level phase.tools list.
export function generateGroundedResponse(
  rng: SeededRNG,
  phase: AttackPhase,
  profile: TargetProfile,
  domain: string,
  isFailure: boolean,
  toolOutputSummary: string,
  hasThinking: boolean,
  actualTools: string[] = []
): string {
  // FIX #2: 40% with headers, 60% without — natural conversation
  const useHeader = rng.bool(0.4);
  let response = "";

  if (useHeader) {
    response += rng.pick([
      `## ${phase.phase}\n\n`,
      `### ${phase.phase}\n\n`,
      `**${phase.phase}:**\n\n`,
      `**${phase.phase} Results**\n\n`,
    ]);
  }

  // FIX #7: Build opening that references ACTUAL tool output
  const opening = generateAnalysisResponse(rng, phase, profile, domain, isFailure, actualTools);

  // FIX #18: mandatory tool attribution in post-observation analysis.
  // When tool_calls actually ran this turn, the analysis MUST name at least
  // one of them — otherwise the model learns to describe findings without
  // referencing where the evidence came from. The opening and fragment
  // pools already pick from actualTools, but nothing guarantees the name
  // survives into the rendered string, so we append a short attribution
  // line that cannot be rng'd away.
  let mandatoryAttribution = "";
  if (actualTools.length > 0) {
    const t = rng.pick(actualTools);
    const verb = rng.pick([
      "Looking at the",
      "Reviewing the",
      "From the",
      "Based on the",
      "Inspecting the",
    ]);
    const tail = isFailure
      ? rng.pick([
          "output, the attempt did not yield the evidence I was probing for.",
          "output, I can see why this particular vector did not succeed here.",
          "output, the failure signal is clear enough to document and move on.",
        ])
      : rng.pick([
          "output, the signal I was looking for is present.",
          "output, the evidence supports the next step of the attack chain.",
          "output, this is the concrete detail I needed before escalating.",
          "output, the pattern matches what a vulnerable endpoint looks like.",
        ]);
    mandatoryAttribution = `\n\n${verb} \`${t}\` ${tail}`;
  }

  // FIX #7: Add grounding paragraph that references tool output data
  let grounding = "";
  if (toolOutputSummary.length > 20 && rng.bool(0.7)) {
    // Extract key details from tool output to reference
    const portMatch = toolOutputSummary.match(/\b(\d{2,5})\/tcp\b/);
    const statusMatch = toolOutputSummary.match(/\b(200|301|302|403|404|500)\b/);
    const serviceMatch = toolOutputSummary.match(/\b(nginx|apache|mysql|postgresql|redis|ssh|http|tomcat)\b/i);
    const versionMatch = toolOutputSummary.match(/\b(\d+\.\d+\.\d+)\b/);

    const refs: string[] = [];
    if (portMatch) refs.push(`port ${portMatch[1]}`);
    if (statusMatch) refs.push(`HTTP ${statusMatch[1]} response`);
    if (serviceMatch) refs.push(`${serviceMatch[1]} service`);
    if (versionMatch) refs.push(`version ${versionMatch[1]}`);

    if (refs.length > 0) {
      grounding = `\n\nSpecifically, the tool output shows ${refs.join(", ")} — ${rng.pick([
        "this confirms my initial assessment",
        "this is consistent with the vulnerability pattern",
        "this narrows down the attack vector",
        "this gives me a concrete target for the next test",
        "this data is key evidence for the report",
        "I can use this to craft a more targeted payload",
      ])}.`;
    }
  }

  // FIX #3 + #13: For failure/soft-fail, include observation-aware narrative.
  // Earlier runs contradicted observations — e.g. "Connection refused" followed
  // by "rate limiting was effective". Pick the failure class from the actual
  // observation so analysis matches what the tool returned.
  let failureNote = "";
  if (isFailure) {
    const cls = classifyFailure(toolOutputSummary);
    const byClass: Record<string, string[]> = {
      unreachable: [
        "**Result: target unreachable.** The tool could not complete the request — the host is either offline, behind a firewall blocking this source, or the service is down. No vulnerability signal either way.",
        "The connection was refused before any application-layer test ran. I can't conclude anything about this endpoint from this attempt — need to retry or pivot.",
        "Connection-level failure. The evidence here is about infrastructure state, not application security. I'll document the attempt and move on.",
      ],
      ratelimited: [
        "**Result: rate-limited.** The target started throttling before I could fully exercise this vector. Inconclusive — I'd need to slow the test or rotate sources to get a clean read.",
        "HTTP 429 responses cut the test short. The control is effective at this rate, but that doesn't confirm the underlying endpoint is safe — just that I can't test it at volume.",
      ],
      blocked: [
        "**Result: blocked by protective control.** The WAF / input filter intercepted the payloads. This attack class is mitigated at the edge; the underlying endpoint may still be vulnerable if the control can be bypassed.",
        "The protective layer caught the payloads consistently. Worth trying encoding, case variation, or a different vector, but for the current technique: blocked.",
      ],
      timeout: [
        "**Result: request timed out.** No conclusive signal — the target may be slow, behind a proxy, or dropping this request class. Inconclusive rather than safe.",
      ],
      generic: [
        "**Result: not vulnerable to this specific technique.** The endpoint handled the payload class correctly. I'll document this as a negative test and pivot to another vector.",
        "No exploitable behavior detected in this test. Input validation for this attack class appears to be working. I'll try adjacent vectors before concluding the endpoint is safe overall.",
      ],
    };
    failureNote = `\n\n${rng.pick(byClass[cls] || byClass.generic)}`;
  }

  // FIX #4: Longer response when thinking is present (thinking should produce deeper analysis)
  let deeperAnalysis = "";
  if (hasThinking && !isFailure && rng.bool(0.6)) {
    deeperAnalysis = `\n\n${rng.pick([
      `**Technical depth:** The root cause is that the ${rng.pick(profile.technologies)} application ${rng.pick(["passes user input directly to " + profile.databases.name + " without parameterization", "uses string concatenation in the template rendering context", "trusts client-supplied data for authorization decisions", "fails to validate the URL scheme before making server-side requests", "accepts unsigned tokens without algorithm verification"])}. The fix requires changes at the ${rng.pick(["data access layer", "middleware level", "controller logic", "framework configuration", "authentication pipeline"])}.`,
      `**Exploitation path:** From this finding, the attack chain is: ${rng.pick(profile.injectableParams)} injection → ${rng.pick(["data extraction", "authentication bypass", "privilege escalation", "internal network access", "code execution"])} → ${rng.pick(["full database dump", "admin account takeover", "server compromise", "cloud credential theft", "lateral movement to internal services"])}. Each step increases the severity.`,
      `**Scope assessment:** This isn't isolated to one endpoint. The ${rng.pick(profile.technologies)} codebase likely has ${rng.int(3, 15)} other endpoints using the same vulnerable pattern because they share ${rng.pick(["the same data access function", "a common middleware", "the same ORM configuration", "a base controller class"])}. I should test ${rng.pickN(profile.injectableParams, 2).join(" and ")} on other endpoints too.`,
    ])}`;
  }

  return `${response}${opening}${mandatoryAttribution}${grounding}${failureNote}${deeperAnalysis}`;
}

// Response Variation Engine (opening sentence generator)
export function generateAnalysisResponse(
  rng: SeededRNG,
  phase: AttackPhase,
  profile: TargetProfile,
  domain: string,
  isFailure: boolean,
  actualTools: string[] = []
): string {
  // Dynamic header — combine phase name with unique framing
  const headerStyles = [
    `## ${phase.phase}\n\n${phase.description}`,
    `### ${phase.phase}\n\nObjective: ${phase.description}`,
    `**Phase: ${phase.phase}**\n\nGoal: ${phase.description}`,
    `## ${phase.phase} — ${rng.pick(profile.technologies)} Target Analysis`,
    `### ${phase.phase} on ${domain}`,
    `## ${rng.pick(["Executing", "Running", "Performing", "Conducting", "Initiating"])} ${phase.phase}`,
    `### ${phase.phase} — ${rng.pick(["Results and Analysis", "Findings Summary", "Assessment Results", "Testing Output"])}`,
    `## ${phase.phase}\n\nTarget: ${domain} (${profile.technologies.join("/")}, ${profile.databases.name})`,
  ];

  // Construct UNIQUE opening sentences from random parts — no two are alike
  const techStr = rng.pick(profile.technologies);
  const dbStr = profile.databases.name;
  const paramStr = rng.pick(profile.injectableParams);
  const portStr = String(rng.pick(profile.openPorts));
  const subStr = rng.pick(profile.subdomains);
  // Prefer the names of the tools that actually ran. Only fall back to the
  // scenario's phase.tools list when no actual call happened (non-tool-calling
  // phase), so narration never names a tool that was not invoked.
  const toolStr = rng.pick(actualTools.length > 0 ? actualTools : phase.tools);
  const payloadCount = rng.int(3, 50);
  const responseTime = rng.int(12, 4500);
  const statusCode = rng.pick([200, 301, 302, 400, 403, 404, 500, 502, 503]);
  const errorDetail = rng.pick([
    "a stack trace exposing internal paths",
    `a ${dbStr} syntax error in the response body`,
    "an unhandled exception with debug info",
    "a verbose error revealing the query structure",
    "differential response lengths between payloads",
    "a timing discrepancy of " + rng.int(200, 3000) + "ms",
    "reflected input without encoding",
    `a ${statusCode} status with a ${rng.int(200, 9000)}-byte body`,
    "a JSON error object containing internal service names",
    "base64-encoded debug output in a response header",
  ]);

  // FULLY DYNAMIC opening sentence construction — every sentence is unique
  // by combining 3 independent sentence fragments from large pools
  const param2 = rng.pick(profile.injectableParams.filter(p => p !== paramStr) || profile.injectableParams);

  let opening: string;
  if (!isFailure) {
    // Fragment A: How the test was conducted (40 options)
    const fragA = rng.pick([
      `${toolStr} against ${subStr}.${domain}:${portStr}`,
      `sending ${payloadCount} payloads to \`${paramStr}\` on ${subStr}.${domain}`,
      `my ${toolStr} scan of ${domain}:${portStr} (${responseTime}ms)`,
      `probing the ${techStr} endpoint at ${subStr}.${domain}`,
      `testing the \`${paramStr}\` parameter on port ${portStr} of ${domain}`,
      `a targeted ${toolStr} assessment of ${subStr}.${domain}`,
      `fuzzing \`${paramStr}\` and \`${param2}\` on ${domain}:${portStr}`,
      `analyzing ${payloadCount} HTTP responses from ${subStr}.${domain}`,
      `${toolStr} enumeration of the ${techStr}/${dbStr} stack on ${domain}`,
      `the ${toolStr} probe of ${subStr}.${domain}:${portStr} (${payloadCount} requests)`,
      `manual testing of \`${paramStr}\` on ${subStr}.${domain} via ${toolStr}`,
      `a ${responseTime}ms ${toolStr} sweep across ${domain}:${portStr}`,
      `comparing baseline vs injected responses on ${subStr}.${domain}`,
      `injecting ${payloadCount} variants into \`${paramStr}\` at ${domain}:${portStr}`,
      `the ${payloadCount}-request ${toolStr} barrage against ${subStr}.${domain}`,
      `fingerprinting ${domain}:${portStr} and then targeting \`${paramStr}\``,
      `piping ${toolStr} output through custom filters on ${subStr}.${domain}`,
      `a time-based analysis of \`${paramStr}\` on ${domain}:${portStr}`,
      `${toolStr} with ${payloadCount} crafted payloads against ${subStr}.${domain}`,
      `probing both \`${paramStr}\` and \`${param2}\` endpoints on ${domain}`,
      `a differential analysis between normal and malicious input to ${subStr}.${domain}:${portStr}`,
      `the ${techStr} application's \`${paramStr}\` handler on ${domain}`,
      `${payloadCount} mutation tests via ${toolStr} against ${subStr}.${domain}`,
      `sequential testing of ${domain}:${portStr} parameters starting with \`${paramStr}\``,
      `${toolStr} running at ${rng.int(50, 200)} requests/sec against ${subStr}.${domain}`,
      `targeting the ${dbStr}-backed \`${paramStr}\` endpoint on ${domain}`,
      `a ${rng.pick(["comprehensive", "systematic", "focused", "thorough", "methodical"])} ${toolStr} assessment of ${subStr}.${domain}:${portStr}`,
      `cross-endpoint testing of \`${paramStr}\` across ${domain} subdomains`,
      `the initial ${toolStr} reconnaissance of ${subStr}.${domain}`,
      `correlating ${toolStr} findings with the ${techStr} version on port ${portStr}`,
    ]);

    // Fragment B: What was observed (30 options)
    const fragB = rng.pick([
      `revealed ${errorDetail}`,
      `confirmed the \`${paramStr}\` parameter is injectable`,
      `produced ${errorDetail} in ${responseTime}ms`,
      `triggered ${statusCode} responses with ${errorDetail}`,
      `exposed a clear ${dbStr} interaction vulnerability`,
      `showed the ${techStr} backend fails to sanitize \`${paramStr}\``,
      `returned ${errorDetail} across ${payloadCount} test cases`,
      `detected unsanitized input reaching the ${dbStr} query layer`,
      `flagged ${errorDetail} on the \`${paramStr}\` handler`,
      `demonstrated that \`${paramStr}\` is passed directly to ${dbStr}`,
      `immediately highlighted ${errorDetail}`,
      `uncovered ${errorDetail} — a strong positive signal`,
      `yielded ${payloadCount} anomalous responses showing ${errorDetail}`,
      `proved the \`${paramStr}\` endpoint lacks proper input validation`,
      `exposed the ${techStr} application's failure to encode \`${paramStr}\``,
      `confirmed exploitability with ${errorDetail}`,
      `produced definitive evidence: ${errorDetail}`,
      `pinpointed ${errorDetail} on the ${dbStr}-backed endpoint`,
      `showed a ${rng.int(50, 3000)}-byte response differential between normal and injected input`,
      `found that ${rng.int(60, 95)}% of payloads bypassed the input filter`,
    ]);

    // Fragment C: Conclusion/significance (20 options)
    const fragC = rng.pick([
      `This confirms the vulnerability is real and exploitable.`,
      `The ${techStr}/${dbStr} stack is clearly handling \`${paramStr}\` unsafely.`,
      `This is a confirmed true positive requiring immediate remediation.`,
      `Exploitation is straightforward from this point.`,
      `The finding affects all requests through this endpoint.`,
      `This validates my initial hypothesis about the ${paramStr} injection point.`,
      `The evidence is conclusive — this endpoint is vulnerable.`,
      `I can reliably reproduce this across multiple request patterns.`,
      `This is consistent with ${rng.pick(["CWE-89", "CWE-79", "CWE-918", "CWE-639", "CWE-94", "CWE-502", "CWE-287"])} exploitation.`,
      `Further exploitation should yield ${rng.pick(["database access", "authentication bypass", "code execution", "data exfiltration", "privilege escalation"])}.`,
      `The vulnerable code path is reachable by any ${rng.pick(["authenticated", "low-privilege", "unauthenticated"])} user.`,
      `This warrants immediate testing for escalation potential.`,
      `Combined with the recon data, this opens several exploitation paths.`,
      `I verified this is not a false positive by testing ${rng.int(3, 10)} payload variants.`,
      `The ${techStr} framework's default configuration appears to lack protection here.`,
    ]);

    opening = `${rng.pick(["After", "Running", "Based on", "Through", "Via", "Following", "During", "From", "With"])} ${fragA}, I ${rng.pick(["found that the results", "confirmed that the output", "observed that the response", "determined that the behavior", "noted that the results"])} ${fragB}. ${fragC}`;
  } else {
    // Build failure opening from starter + unique context fragments
    const defenseType = rng.pick(["WAF", "input filter", "rate limiter", "security middleware", "validation layer", "parameterized query layer"]);
    const defenseDetail = rng.pick([
      `returned consistent ${statusCode} responses regardless of payload`,
      `blocked ${payloadCount} of my test payloads within ${responseTime}ms`,
      `stripped injection characters before they reached the ${dbStr} backend`,
      `responded with generic error messages hiding implementation details`,
      `enforced strict Content-Type validation on every request`,
      `rate-limited my ${toolStr} scan after ${rng.int(3, 25)} requests`,
      `showed identical response timing across all ${payloadCount} payloads`,
      `rejected all non-alphanumeric input in the \`${paramStr}\` parameter`,
    ]);
    // Dynamic failure opening — same fragment construction approach
    const failFragA = rng.pick([
      `${toolStr} against ${subStr}.${domain}:${portStr}`,
      `sending ${payloadCount} payloads to \`${paramStr}\` on ${domain}`,
      `my ${toolStr} assessment of ${subStr}.${domain}`,
      `testing the \`${paramStr}\` parameter via ${toolStr} on port ${portStr}`,
      `a ${payloadCount}-request ${toolStr} probe of ${domain}:${portStr}`,
      `probing the ${techStr} endpoint at ${subStr}.${domain}:${portStr}`,
      `fuzzing \`${paramStr}\` on ${subStr}.${domain} with ${toolStr}`,
      `${toolStr} enumeration of ${domain}:${portStr} targeting \`${paramStr}\``,
    ]);
    const failFragB = rng.pick([
      `the ${defenseType} ${defenseDetail}`,
      `a ${defenseType} blocked my payloads — it ${defenseDetail}`,
      `the \`${paramStr}\` parameter proved resilient because the ${defenseType} ${defenseDetail}`,
      `the ${techStr} application's ${defenseType} effectively ${defenseDetail}`,
      `the endpoint's ${defenseType} on port ${portStr} ${defenseDetail}`,
    ]);
    const failFragC = rng.pick([
      `This is a dead end for this specific technique — I need to pivot.`,
      `The ${defenseType} is effective, but there may be bypass methods I haven't tried.`,
      `Good defense here, but I'll look for gaps in adjacent endpoints.`,
      `This tells me the developers are security-aware — I need a more creative approach.`,
      `The defense blocks this vector, but the error response reveals useful information about the ${defenseType} implementation.`,
      `I'll document this as a positive finding for the client's security posture and try alternative techniques.`,
    ]);
    opening = `${rng.pick(["After", "Running", "Based on", "Through", "Via", "Following", "During", "From"])} ${failFragA}, I found that ${failFragB}. ${failFragC}`;
  }

  // Generate body with inline exploit code when appropriate
  const body = isFailure
    ? generateFailureAnalysis(rng, phase, profile, domain, actualTools)
    : generateSuccessAnalysis(rng, phase, profile, domain, actualTools);

  // Dynamic next steps — incorporate specific context
  const nextAction = variateText(phase.next_action, domain, profile);
  const nextStepFormats = [
    `**Next step:** ${nextAction}`,
    `**Moving forward:** Based on these results, I'll ${nextAction.charAt(0).toLowerCase() + nextAction.slice(1)}.`,
    `**Action plan:** ${nextAction}. I'll also ${rng.pick(["check for related issues on adjacent endpoints", "verify the finding with an alternative technique", "look for ways to chain this with other findings", "document the evidence for the report"])}.`,
    `**What I'll do next:** ${nextAction}. My hypothesis is that ${rng.pick(["the same pattern exists on other endpoints", "this can be escalated further", "combining this with the earlier finding will increase the severity", "the development team used the same vulnerable pattern elsewhere"])}.`,
    `**Recommended next action:** ${nextAction}`,
    `I'll proceed to ${nextAction.charAt(0).toLowerCase() + nextAction.slice(1)}. Based on the ${rng.pick(profile.technologies)} architecture, ${rng.pick(["the most promising next target is the authentication endpoint", "I expect the API endpoints will share this vulnerability", "the internal services are likely reachable from here", "there may be additional data I can extract"])}.`,
  ];

  return `${rng.pick(headerStyles)}\n\n${opening}\n\n${body}\n\n${rng.pick(nextStepFormats)}`;
}

export function generateSuccessAnalysis(rng: SeededRNG, phase: AttackPhase, profile: TargetProfile, domain: string, actualTools: string[] = []): string {
  const toolPool = actualTools.length > 0 ? actualTools : phase.tools;
  const analysis = variateText(phase.analysis, domain, profile);

  const extras: string[] = [];

  // Hypothesis-driven reasoning (boosted to 60%+)
  if (rng.bool(0.65)) {
    const hypothesisBlocks = [
      `\n\n**Hypothesis validation:** I initially hypothesized that the ${rng.pick(profile.injectableParams)} parameter would be vulnerable because ${rng.pick(["the error messages suggested unsanitized input reaches the backend", "the response timing varied with different payloads indicating server-side processing", "the application reflects user input without encoding in certain contexts", `${rng.pick(profile.technologies)} applications commonly have this issue when using default configurations`, "the API documentation mentioned this field is used in database queries"])}. The test results confirm this hypothesis — the parameter is indeed ${rng.pick(["injectable", "exploitable", "improperly validated", "passed directly to the backend without sanitization"])}.`,
      `\n\n**Reasoning:** My hypothesis was that the ${rng.pick(profile.technologies)} application processes the ${rng.pick(profile.injectableParams)} parameter unsafely. Evidence supporting this:\n1. The response ${rng.pick(["changes predictably based on injected boolean conditions", "includes error details from the " + profile.databases.name + " backend", "timing correlates with payload complexity", "reflects injected content without encoding"])}\n2. The ${rng.pick(["error handling", "input validation", "authorization check", "output encoding"])} is ${rng.pick(["missing", "insufficient", "client-side only", "bypassable with encoding"])}\n3. This is consistent with ${rng.pick(["CWE-89 (SQL Injection)", "CWE-79 (Cross-site Scripting)", "CWE-918 (SSRF)", "CWE-639 (IDOR)", "CWE-94 (Code Injection)"])}`,
      `\n\n**Analysis chain:** Observation → the ${rng.pick(profile.injectableParams)} parameter shows ${rng.pick(["differential responses", "error-based information disclosure", "timing variations", "reflected content"])}. Hypothesis → the input reaches a ${rng.pick(["database query", "template engine", "system command", "file operation", "URL fetch"])} without proper sanitization. Test → sent ${rng.int(3, 20)} targeted payloads. Conclusion → confirmed vulnerability with ${rng.pick(["boolean-based differential responses", "extracted data from the " + profile.databases.name + " backend", "demonstrated code execution", "accessed unauthorized resources", "bypassed access controls"])}.`,
    ];
    extras.push(rng.pick(hypothesisBlocks));
  }

  // Technical context
  if (rng.bool(0.5)) {
    extras.push(`\n\nThe ${rng.pick(profile.technologies)} stack with ${profile.databases.name} backend is relevant because ${rng.pick([
      "this framework version has known issues with input sanitization in certain contexts",
      "the default ORM configuration doesn't prevent all injection vectors",
      "error handling in this stack tends to expose internal implementation details",
      "the middleware chain can be bypassed using specific encoding techniques",
      `${profile.databases.name} supports features that make exploitation easier once injection is confirmed`,
      "the authentication mechanism in this framework has documented bypass techniques",
      "the session management implementation has known timing side-channels",
    ])}.`);
  }

  // FIX #17: Inline exploit code — dialed from 45% to 20% of success turns.
  // Earlier runs put code fences in ~100% of filtered entries, training the
  // model to wedge a fenced block into every analysis. Keep code for when it
  // genuinely adds evidence, not as a reflex.
  if (rng.bool(0.2)) {
    const param = rng.pick(profile.injectableParams);
    const exploitCodeBlocks = [
      `\n\nI wrote a quick verification script to confirm the finding:\n\n\`\`\`python\nimport requests\n\ntarget = "https://${domain}/api/${rng.pick(["search", "users", "data", "query"])}"\nheaders = {"Authorization": "Bearer $TOKEN", "Content-Type": "application/json"}\n\n# Baseline request\nbaseline = requests.get(target, params={"${param}": "normal_value"}, headers=headers)\n\n# Injection test\ninjection = requests.get(target, params={"${param}": "${rng.pick(["' OR 1=1--", "{{7*7}}", "; id", "http://169.254.169.254/", "../../../etc/passwd"])}"}, headers=headers)\n\nprint(f"Baseline: {baseline.status_code} ({len(baseline.text)} bytes)")\nprint(f"Injection: {injection.status_code} ({len(injection.text)} bytes)")\n\nif baseline.status_code != injection.status_code or abs(len(baseline.text) - len(injection.text)) > 50:\n    print("[+] Differential response detected — likely vulnerable!")\nelse:\n    print("[-] Consistent responses — parameter may be safe")\n\`\`\`\n\nThe script confirmed the differential response.`,

      `\n\nTo automate the extraction, I wrote:\n\n\`\`\`bash\n#!/bin/bash\nTARGET="https://${domain}"\nTOKEN="$1"\n\n# Enumerate valid IDs via IDOR\nfor id in $(seq 1 100); do\n  status=$(curl -s -o /dev/null -w "%{http_code}" \\\n    -H "Authorization: Bearer $TOKEN" \\\n    "$TARGET/api/v1/users/$id")\n  if [ "$status" = "200" ]; then\n    echo "[+] Valid ID: $id"\n    curl -s -H "Authorization: Bearer $TOKEN" \\\n      "$TARGET/api/v1/users/$id" | jq '.email,.role'\n  fi\ndone\n\`\`\`\n\nThis enumerated ${rng.int(10, 200)} valid user records in under ${rng.int(5, 30)} seconds.`,

      `\n\nCustom exploitation script:\n\n\`\`\`python\nimport requests\nimport concurrent.futures\n\nBASE_URL = "https://${domain}/api"\nHEADERS = {"Authorization": "Bearer $TOKEN"}\n\ndef test_endpoint(endpoint, param, payload):\n    \"\"\"Test a single endpoint/parameter combination\"\"\"\n    try:\n        resp = requests.get(f"{BASE_URL}/{endpoint}", \n                          params={param: payload}, \n                          headers=HEADERS, timeout=10)\n        return {\n            "endpoint": endpoint,\n            "param": param,\n            "status": resp.status_code,\n            "length": len(resp.text),\n            "interesting": resp.status_code == 500 or "${rng.pick(["error", "exception", "syntax", "SQL"])}" in resp.text.lower()\n        }\n    except Exception as e:\n        return {"endpoint": endpoint, "error": str(e)}\n\n# Test multiple endpoints in parallel\nendpoints = ${JSON.stringify(rng.pickN(["users", "search", "orders", "products", "settings", "admin", "reports", "transactions"], 4))}\npayloads = ["' OR 1=1--", "1 UNION SELECT NULL--", "{{7*7}}", "\$\{7*7\}", "| id"]\n\nwith concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:\n    futures = []\n    for ep in endpoints:\n        for payload in payloads:\n            futures.append(executor.submit(test_endpoint, ep, "${param}", payload))\n    \n    for f in concurrent.futures.as_completed(futures):\n        result = f.result()\n        if result.get("interesting"):\n            print(f"[!] INTERESTING: {result}")\n\`\`\``,

      `\n\nI used this one-liner to quickly extract data:\n\n\`\`\`bash\n# Chain subfinder → httpx → nuclei for automated discovery\nsubfinder -d ${domain} -silent | \\\n  httpx -silent -status-code -title -tech-detect | \\\n  tee alive_hosts.txt | \\\n  awk '{print $1}' | \\\n  nuclei -severity critical,high -silent -o critical_findings.txt\n\necho "[+] Found $(wc -l < critical_findings.txt) critical/high findings"\ncat critical_findings.txt\n\`\`\`\n\nThis pipeline discovered ${rng.int(2, 15)} critical/high severity findings across ${rng.int(5, 20)} live subdomains.`,

      `\n\nQuick PoC to demonstrate the impact:\n\n\`\`\`python\nimport requests\nimport json\n\ns = requests.Session()\ns.headers.update({"Content-Type": "application/json"})\n\n# Step 1: Authenticate as regular user\nauth = s.post("https://${domain}/api/auth/login", \n              json={"email": "test@test.com", "password": "TestPass123!"})\ntoken = auth.json()["token"]\ns.headers["Authorization"] = f"Bearer {token}"\n\n# Step 2: Access another user's data (IDOR)\nfor user_id in range(1, ${rng.int(10, 50)}):\n    r = s.get(f"https://${domain}/api/users/{user_id}")\n    if r.status_code == 200:\n        data = r.json()\n        print(f"[+] User {user_id}: {data.get('email', 'N/A')} | Role: {data.get('role', 'N/A')}")\n\nprint(f"\\n[!] Successfully accessed {user_id} user records without authorization")\n\`\`\``,
    ];
    extras.push(rng.pick(exploitCodeBlocks));
  }

  // Risk context
  if (rng.bool(0.4)) {
    extras.push(`\n\n${rng.pick([
      `From a risk perspective, this finding affects approximately ${rng.int(100, profile.userCount).toLocaleString()} users of the application. The attack complexity is low and requires no special conditions.`,
      `This is a systemic issue — the same vulnerable pattern likely exists across ${rng.int(3, 15)} other endpoints that use the same ${rng.pick(["data access function", "middleware", "controller logic", "validation helper"])}.`,
      `The combination of ${rng.pick(profile.technologies)} and ${profile.databases.name} makes this exploitable with standard tools. No custom exploit development is needed.`,
      `Without remediation, an attacker could automate this at scale — I estimate full data extraction would take under ${rng.int(1, 30)} minutes with a simple script.`,
      `This vulnerability has been exploitable since the ${rng.pick(profile.injectableParams)} parameter was introduced. Based on the application architecture, it's likely been present since the initial deployment.`,
    ])}`);
  }

  // Tool verification — name a tool that actually ran this turn.
  if (rng.bool(0.35)) {
    const toolMention = rng.pick(toolPool);
    extras.push(`\n\n${rng.pick([
      `I verified this using ${toolMention} and manual follow-up requests. Both approaches produced consistent results, confirming this is a true positive.`,
      `The ${toolMention} run initially flagged this. I then manually confirmed it by crafting ${rng.int(3, 10)} targeted payloads to rule out false positives.`,
      `${toolMention} reported ${rng.int(1, 5)} findings on this endpoint. After manual triage, ${rng.int(1, 3)} are confirmed exploitable vulnerabilities.`,
    ])}`);
  }

  return analysis + extras.join("");
}

export function generateFailureAnalysis(rng: SeededRNG, phase: AttackPhase, profile: TargetProfile, domain: string, actualTools: string[] = []): string {
  const toolPool = actualTools.length > 0 ? actualTools : phase.tools;
  const failureReasons = [
    `The application's input validation caught my test payloads. The ${rng.pick(profile.technologies)} framework appears to have built-in protection against this specific attack class.`,
    `A WAF or input filter is stripping/blocking the injection characters before they reach the backend. I observed ${rng.pick(["HTTP 403 responses", "HTML-encoded output", "silently dropped characters", "generic error messages replacing the expected behavior"])}.`,
    `The endpoint returned consistent responses regardless of payload variation, suggesting the parameter is properly ${rng.pick(["parameterized", "sanitized", "validated", "encoded"])} before being processed.`,
    `Rate limiting kicked in after ${rng.int(3, 20)} requests. The application implements request throttling that limits automated testing.`,
    `The response timing is consistent across all payloads, ruling out time-based blind injection. The backend appears to use ${rng.pick(["parameterized queries", "an ORM", "prepared statements", "a security middleware layer"])}.`,
    `The application correctly validates the Content-Type and rejects malformed requests. The security headers (${rng.pick(["CSP", "X-Content-Type-Options", "X-Frame-Options"])}) are also properly configured.`,
    `No reflected content was found in the response. The application appears to use a modern ${rng.pick(profile.technologies)} framework with built-in output encoding.`,
  ];

  let analysis = rng.pick(failureReasons);

  analysis += `\n\n${rng.pick([
    "This doesn't mean the application is fully secure — it means this specific attack vector is mitigated. I'll adjust my approach and try alternative techniques.",
    "The failure is informative. It tells me the developers have implemented at least basic security controls. I need to find gaps in their coverage.",
    "I'll document this negative result in the report. It's important to note what defenses ARE working, not just what's broken.",
    "This is a good sign for the client's security posture, but I'll continue testing with more creative approaches.",
    "The defense is effective against this specific technique, but there may be bypass methods I haven't tried yet.",
  ])}`;

  analysis += `\n\n**Pivot plan:** ${rng.pick([
    "I'll try the same vulnerability class with different encoding techniques to bypass the filter.",
    "I'll test adjacent endpoints that might share vulnerable code but lack the same protection.",
    "I'll switch to manual testing with targeted payloads instead of automated scanning.",
    `I'll write a custom Python script to test edge cases that ${rng.pick(toolPool)} might miss.`,
    "I'll test using different HTTP methods — sometimes only one method is properly validated.",
    "I'll look for second-order injection points where the payload is stored and triggered in a different context.",
    `I'll check if the ${rng.pick(["API", "mobile API", "v1 API", "internal API"])} has the same protection.`,
  ])}`;

  return analysis;
}
