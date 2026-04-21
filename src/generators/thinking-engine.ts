// Deep Thinking & Reasoning Engine
// Generates unique, detailed chain-of-thought reasoning blocks
// Models real pentester cognitive process: observe → hypothesize → plan → execute → analyze → pivot

import { SeededRNG, TargetProfile, DynamicOutputEngine } from "./outputs/index.js";

export class ThinkingEngine {
  private rng: SeededRNG;

  constructor(seed: number) {
    this.rng = new SeededRNG(seed);
  }

  // ============================================================
  // Phase-specific thinking generators
  // ============================================================

  generateReconThinking(domain: string, profile: TargetProfile, discoveredInfo: string[]): string {
    const approach = this.rng.pick(RECON_THINKING_TEMPLATES);
    return this.fillThinkingTemplate(approach, {
      domain,
      ip: profile.ip,
      techs: profile.technologies.join(", "),
      ports: profile.openPorts.slice(0, 5).join(", "),
      subCount: String(this.rng.int(5, 30)),
      discoveries: discoveredInfo.join("; "),
      dbType: profile.databases.name,
      headers: profile.techHeaders[0] || "unknown",
    });
  }

  generateEnumThinking(domain: string, profile: TargetProfile, phase: string): string {
    const approach = this.rng.pick(ENUM_THINKING_TEMPLATES);
    return this.fillThinkingTemplate(approach, {
      domain,
      directories: profile.directories.slice(0, 5).join(", "),
      params: profile.injectableParams.join(", "),
      techs: profile.technologies.join("/"),
      dbType: profile.databases.name,
      endpoints: this.rng.int(5, 30).toString(),
    });
  }

  generateVulnAnalysisThinking(domain: string, profile: TargetProfile, vulnType: string, evidence: string): string {
    const approach = this.rng.pick(VULN_THINKING_TEMPLATES);
    return this.fillThinkingTemplate(approach, {
      domain,
      vulnType,
      evidence,
      param: this.rng.pick(profile.injectableParams),
      techs: profile.technologies.join("/"),
      dbType: profile.databases.name,
      impact: this.rng.pick(["data breach", "account takeover", "remote code execution", "privilege escalation", "information disclosure", "full system compromise"]),
    });
  }

  generateExploitThinking(domain: string, profile: TargetProfile, vulnType: string, exploitResult: string): string {
    const approach = this.rng.pick(EXPLOIT_THINKING_TEMPLATES);
    return this.fillThinkingTemplate(approach, {
      domain,
      vulnType,
      exploitResult,
      techs: profile.technologies.join("/"),
      dbType: profile.databases.name,
      osUser: this.rng.pick(["www-data", "node", "appuser", "tomcat", "nginx", "spring", "django", "rails"]),
      nextSteps: this.rng.pickN(["lateral movement", "credential harvesting", "persistence", "data exfiltration", "privilege escalation", "pivot to internal network"], 3).join(", "),
    });
  }

  generateFailureThinking(domain: string, profile: TargetProfile, whatFailed: string, why: string): string {
    // When the observation indicates the target was simply unreachable (or the
    // request timed out), the generic FAILURE_THINKING_TEMPLATES — which assume
    // a WAF / input validation block — are causally wrong. Route to a dedicated
    // network-level template so the reasoning doesn't claim a security control
    // was effective when in reality no request reached the application.
    const isNetworkFailure = /unreachable|offline|timed out|timeout/i.test(why);
    const approach = isNetworkFailure
      ? this.rng.pick(NETWORK_FAILURE_THINKING_TEMPLATES)
      : this.rng.pick(FAILURE_THINKING_TEMPLATES);
    return this.fillThinkingTemplate(approach, {
      domain,
      whatFailed,
      why,
      techs: profile.technologies.join("/"),
      alternativeApproach: this.rng.pick([
        "try a different injection technique with higher level/risk settings",
        "test alternative endpoints that may share the same vulnerable code path",
        "look for WAF bypass techniques specific to this technology stack",
        "try encoding the payload differently to evade input filtering",
        "switch to a time-based technique since boolean-based was detected",
        "test for second-order injection in a different context",
        "try testing the same parameter via a different HTTP method",
        "look for related parameters that might lack the same protection",
        "use a different tool that handles this edge case better",
        "attempt out-of-band techniques since in-band failed",
        "check if there's an API version without the security fix",
        "try header-based injection since body parameters are filtered",
      ]),
      pivotReason: this.rng.pick([
        "the WAF is blocking my payloads but might miss encoded variants",
        "the parameter validation is server-side but might have inconsistencies",
        "this endpoint is patched but older API versions might not be",
        "direct exploitation failed but I can try chaining with another finding",
        "the application uses a framework that has known bypass techniques",
        "error messages suggest a different backend than initially assumed",
        "rate limiting kicked in, need to slow down and be more targeted",
        "the response behavior suggests there might be a different injectable point",
      ]),
    }, /* isFailure */ true);
  }

  generatePostExploitThinking(domain: string, profile: TargetProfile, accessLevel: string): string {
    const approach = this.rng.pick(POST_EXPLOIT_THINKING_TEMPLATES);
    return this.fillThinkingTemplate(approach, {
      domain,
      accessLevel,
      techs: profile.technologies.join("/"),
      dbType: profile.databases.name,
      internalServices: this.rng.pickN(["Redis", "Elasticsearch", "MongoDB", "RabbitMQ", "Memcached", "Consul", "etcd", "internal API gateway"], 3).join(", "),
      sensitiveData: this.rng.pickN(["user PII", "payment card data", "session tokens", "API keys", "database credentials", "SSL private keys", "internal documentation", "source code"], 4).join(", "),
    });
  }

  generateEvasionThinking(domain: string, profile: TargetProfile, blockedBy: string, blockDetails: string): string {
    const approach = this.rng.pick(EVASION_THINKING_TEMPLATES);
    return this.fillThinkingTemplate(approach, {
      domain,
      techs: profile.technologies.join("/"),
      whatFailed: blockedBy,
      why: blockDetails,
      alternativeApproach: this.rng.pick([
        "double-URL-encoded payloads to bypass regex-based detection",
        "HTTP parameter pollution with duplicate parameters",
        "chunked transfer encoding to split the payload across chunks",
        "switching to WebSocket protocol which often lacks WAF coverage",
        "testing alternative API versions that predate the WAF rules",
        "using Unicode normalization bypasses for character filtering",
        "out-of-band techniques via DNS exfiltration",
        "finding the origin IP to bypass the CDN/WAF entirely",
      ]),
      pivotReason: this.rng.pick([
        "a Cloudflare-style challenge page pattern",
        "AWS WAF with managed rule groups",
        "ModSecurity with CRS 4.0 rules",
        "a custom application-layer input filter",
        "Akamai's Kona Site Defender",
        "a reverse proxy with regex-based filtering",
        "an API gateway with request validation schemas",
      ]),
    });
  }

  generateReportThinking(domain: string, vulnType: string, severity: string, chainedFindings: string[]): string {
    const approach = this.rng.pick(REPORT_THINKING_TEMPLATES);
    return this.fillThinkingTemplate(approach, {
      domain,
      vulnType,
      severity,
      chainedFindings: chainedFindings.join(" → "),
      complianceImpact: this.rng.pickN(["GDPR Article 32", "PCI-DSS Requirement 6.5", "HIPAA Security Rule", "SOC 2 Type II CC6.1", "ISO 27001 A.14.2", "NIST SP 800-53 SI-10"], 2).join(", "),
      cvssVector: `AV:N/AC:${this.rng.pick(["L", "H"])}/PR:${this.rng.pick(["N", "L", "H"])}/UI:${this.rng.pick(["N", "R"])}/S:${this.rng.pick(["U", "C"])}/C:${this.rng.pick(["H", "L", "N"])}/I:${this.rng.pick(["H", "L", "N"])}/A:${this.rng.pick(["H", "L", "N"])}`,
    });
  }

  // ============================================================
  // Template filling
  // ============================================================

  private fillThinkingTemplate(template: string, vars: Record<string, string>, isFailure = false): string {
    let result = template;

    // Inject hypothesis-driven reasoning prefix — but only for success paths.
    // Failure thinking reasoning must not open with "what does the application
    // behavior tell me about its internals" when the observation was
    // Connection refused or a WAF block.
    if (!isFailure && this.rng.bool(0.6)) {
      const hypothesisPrefixes = [
        `My working hypothesis: ${vars.domain || "the target"} is likely vulnerable because ${this.rng.pick(["the technology stack has known default misconfigurations", "the error responses suggest improper input handling", "the API design follows patterns commonly associated with authorization flaws", "the response behavior is inconsistent between normal and anomalous input", "the framework version is known to have security issues in this area"])}. Let me test this systematically.\n\n`,
        `Before diving in, let me form hypotheses about what I expect to find:\n- Hypothesis A: The ${vars.param || "input"} parameter is processed unsafely → test with injection probes\n- Hypothesis B: Authorization checks are missing at the object level → test with ID manipulation\n- Hypothesis C: The ${vars.techs || "application"} error handling leaks sensitive details → test with malformed input\nI'll test each hypothesis and eliminate the ones that don't hold.\n\n`,
        `Cognitive process for this phase:\n1. OBSERVE: What does the application behavior tell me about its internals?\n2. HYPOTHESIZE: Based on the ${vars.techs || "technology stack"} and observed behavior, what vulnerabilities are most likely?\n3. TEST: Design specific probes to confirm or deny each hypothesis\n4. CONCLUDE: Draw evidence-based conclusions and plan the next step\n\n`,
      ];
      result = this.rng.pick(hypothesisPrefixes) + result;
    }

    for (const [key, value] of Object.entries(vars)) {
      result = result.replace(new RegExp(`\\{${key}\\}`, "g"), value);
    }
    return result;
  }
}

// ============================================================
// Thinking Templates — DEEP, VARIED reasoning
// ============================================================

const RECON_THINKING_TEMPLATES = [
  `Starting reconnaissance against {domain}. I need to build a comprehensive picture of the attack surface before testing anything.

First, let me analyze what I already know:
- The target resolves to {ip}
- Initial technology fingerprinting suggests {techs}
- I can see ports {ports} are likely open

My reconnaissance strategy:
1. Passive subdomain enumeration first — I don't want to trigger any alerts. I'll use certificate transparency logs, DNS records, and web archives to discover subdomains without sending a single packet to the target.
2. Once I have a subdomain list, I'll probe them with httpx to identify live hosts, their HTTP status codes, page titles, and technology stack. This tells me which subdomains are interesting targets.
3. For each live subdomain, I'll run directory enumeration to discover hidden endpoints, admin panels, API documentation, backup files, and exposed configuration.
4. I'll also check for cloud assets — S3 buckets named after the domain, exposed cloud metadata endpoints.

What I'm specifically looking for:
- Admin panels or management interfaces (often less hardened than public-facing apps)
- API endpoints (often have weaker authorization than the web UI)
- Development/staging environments (often have debug mode enabled, default credentials, or relaxed security)
- Exposed git repositories, backup files, or configuration files
- Third-party integrations that might be misconfigured

Based on the {techs} stack, I should pay special attention to:
${"{techs}".includes("Node") ? "- Express middleware misconfigurations, exposed /debug routes, package.json with dependency information" : ""}
${"{techs}".includes("Java") ? "- Spring Boot actuator endpoints (/actuator/env, /actuator/health), Apache Tomcat manager panel" : ""}
${"{techs}".includes("PHP") ? "- phpinfo.php, exposed .htaccess, wp-admin if WordPress, Laravel debug mode" : ""}
${"{techs}".includes("Python") ? "- Flask/Django debug mode, __pycache__ exposure, Werkzeug debugger" : ""}
- Common misconfigurations for {dbType} database exposure

My initial findings so far: {discoveries}. Let me analyze these and prioritize my next steps.`,

  `Alright, let me approach this reconnaissance methodically. Target: {domain} ({ip}).

Phase 1 — Subdomain Discovery:
I'll start with passive techniques to enumerate as many subdomains as possible. The goal is to map the entire external attack surface. Large organizations often have forgotten subdomains pointing to deprecated services, staging environments with relaxed security, or internal tools accidentally exposed to the internet.

I found approximately {subCount} subdomains. Now I need to:
- Check which ones resolve and are reachable (httpx)
- Identify the technology stack on each (headers, response fingerprinting)
- Flag any that show interesting status codes (403 could mean there's something worth bypassing, 500 could mean vulnerable error handling)

Phase 2 — Technology Profiling:
The headers reveal {headers}, which tells me this is a {techs} stack. This is important because:
- Each framework has its own set of common vulnerabilities and misconfigurations
- The database backend ({dbType}) determines what SQL injection payloads will work
- The web server determines what path traversal and header manipulation techniques apply

Phase 3 — Attack Surface Prioritization:
Not all endpoints are equal. I'm looking for:
1. Authentication endpoints — these handle credentials and sessions, highest value target
2. API endpoints — often have less restrictive input validation than web forms
3. File upload/download — potential for path traversal, SSRF, or unrestricted upload
4. Search/filter functionality — common injection points
5. Admin/management interfaces — if accessible, usually game over

Key observations so far: {discoveries}`,

  `Let me think about how to approach {domain} systematically.

The IP {ip} and initial response headers suggest {techs}. This gives me a solid starting point for targeted enumeration.

My mental model for this assessment:
- The application is running {techs} which means I should focus on vulnerabilities common in this stack
- The database appears to be {dbType}, so my SQL injection payloads need to be dialect-specific
- I found {subCount} subdomains, which is a moderate attack surface

Critical thinking about what I've found so far:
{discoveries}

Before I start active testing, I want to understand the security posture:
- Are there WAF/CDN indicators? (Cloudflare, Akamai, AWS WAF headers)
- Do error responses leak stack traces or internal paths?
- Are CORS headers permissive?
- Is the CSP header present and restrictive?
- Are cookies marked HttpOnly and Secure?

These defensive indicators will determine my approach — if there's a WAF, I need to be more careful with my payloads and may need encoding/obfuscation techniques. If there's no CSP, stored XSS becomes more impactful. If cookies lack HttpOnly, session hijacking via XSS is straightforward.

Let me continue the enumeration and start identifying specific entry points.`,
];

const ENUM_THINKING_TEMPLATES = [
  `Directory and endpoint enumeration is revealing interesting results on {domain}.

Discovered paths so far: {directories}
This tells me several things:
1. The application structure follows a {techs} convention
2. There are {endpoints} accessible endpoints across different functionality areas
3. Some paths returned 403 instead of 404 — meaning the resource EXISTS but I'm not authorized. These are prime targets for access control bypass.

Parameter analysis is crucial here. I found these parameters: {params}

For each parameter, I need to determine:
- What type of data it accepts (integer, string, URL, file path)
- Whether it's reflected in the response (XSS potential)
- Whether it's used in database queries (SQLi potential)
- Whether it fetches external resources (SSRF potential)
- Whether it references objects by ID (IDOR potential)

My priority testing order:
1. Parameters that accept IDs or references → test for IDOR/BOLA
2. Parameters in search/filter functionality → test for SQLi
3. Parameters reflected in HTML → test for XSS
4. Parameters that accept URLs → test for SSRF
5. File/path parameters → test for LFI/path traversal

The {dbType} backend means I should use specific payloads for this DBMS dialect. Common differences include comment syntax, string concatenation, and time delay functions.`,

  `I'm mapping the application's endpoint structure on {domain}.

Found directories: {directories}

The pattern I'm seeing suggests this is a standard {techs} application with:
- Public-facing endpoints (low security value but good for understanding the app)
- API endpoints (usually the most interesting for injection and authorization testing)
- Administrative endpoints (highest value if accessible)

For parameter discovery, I'll use multiple techniques:
1. Crawling visible pages and extracting parameters from forms, JavaScript, and links
2. Fuzzing with common parameter names using Arjun
3. Checking web archives (gau, wayback) for historical parameters that might still work
4. Analyzing JavaScript files for API calls and hidden parameters

Currently identified parameters: {params}

One thing that stands out — the way parameters are named suggests the developers might be using direct database column names as API parameters. This is a common anti-pattern that often leads to mass assignment vulnerabilities (if I can guess hidden parameters like "role" or "is_admin", the API might accept them even though they're not in the documentation).

Next, I'll test each parameter with basic injection probes to see which ones look promising before doing deep exploitation.`,

  `Mapping the attack surface of {domain} — let me think about what these enumeration results mean.

The directory structure reveals: {directories}
Discovered {endpoints} total endpoints.

What catches my eye:
- Any .git, .env, or config paths → potential information disclosure that gives me an advantage
- API versioning (v1, v2) → older API versions often lack security fixes present in newer ones
- Admin/dashboard paths → even if 403, worth testing header bypass, path traversal, or parameter tampering
- Debug/health/metrics endpoints → often leak internal state, environment variables, or dependency information

The parameter landscape ({params}) suggests several attack vectors I should test systematically. Rather than spraying payloads blindly, I want to understand how each parameter is processed:
- Send a normal value and analyze the response structure
- Send an empty value — does it error differently?
- Send a very long value — does it truncate or cause an error that leaks information?
- Send special characters (' " < > {{ | ; \` $) — which ones cause errors vs get filtered vs get reflected?

This behavioral analysis tells me more about the backend processing than any automated scanner could.`,
];

const VULN_THINKING_TEMPLATES = [
  `I've identified a potential {vulnType} vulnerability on {domain}.

Evidence: {evidence}

Let me analyze this carefully before confirming.

The parameter '{param}' in the {techs} application appears to be vulnerable because:
1. The response behavior changes based on my injected payload — this is a strong positive signal
2. The error message (if any) reveals backend details that shouldn't be exposed
3. The input is not being properly sanitized or parameterized before being used in the server-side operation

Before I declare this confirmed, I need to rule out false positives:
- Could the response difference be caused by something other than successful injection?
- Is the application using a WAF that might be mangling my payload and causing a different error?
- Could this be a client-side validation only, with the server actually handling it safely?

To confirm, I'll:
1. Send a "true" condition payload and a "false" condition payload — compare responses
2. Use increasingly specific payloads to determine the exact injection context
3. Test if I can extract actual data vs just getting a boolean response
4. Determine the scope of impact — what data can I access? Can I modify data? Can I escalate to OS access?

If this confirms as {vulnType}, the impact assessment is:
- Confidentiality: I could potentially extract {impact}
- Integrity: If write operations are possible, I could modify data
- Availability: Depending on the injection context, I might be able to cause denial of service

This aligns with {vulnType} which is a known high-severity vulnerability class. Let me proceed with careful exploitation to fully demonstrate the impact.`,

  `Analyzing what I'm seeing on {domain} — the behavior strongly suggests {vulnType}.

The specific evidence is: {evidence}

My reasoning process:
1. I sent a baseline request with normal input to the '{param}' parameter and recorded the response.
2. I then sent a modified request with an injection payload. The response was different in a way that's consistent with {vulnType}.
3. To eliminate false positives, I sent several variations — the pattern is consistent.

Understanding the vulnerability context:
The {techs} stack is using {dbType} on the backend. Based on the error behavior, the vulnerable code is likely:
- NOT using parameterized queries / prepared statements (for SQLi)
- NOT sanitizing user input before passing to a dangerous sink (for XSS/SSTI/command injection)
- NOT implementing proper access control checks on the object level (for IDOR/BOLA)

The risk is real because:
- This parameter is accessible to any authenticated user (or even unauthenticated in some cases)
- The vulnerability is in a production endpoint, not a debug or test endpoint
- The potential impact extends to {impact}

I need to be thorough but careful — I want to demonstrate maximum realistic impact without causing any actual damage to the production environment. I'll use read-only operations where possible and time-based techniques to avoid data modification.`,

  `Something interesting on {domain}. The '{param}' parameter is behaving abnormally.

What I observed: {evidence}

Let me reason through this step by step.

Hypothesis 1: This is a genuine {vulnType} vulnerability
- Evidence for: The response clearly changes when I inject test payloads
- Evidence against: Could be a WAF or input filter that creates a different error

Hypothesis 2: This is a WAF false positive
- Evidence for: The error response doesn't contain typical database/template error signatures
- Evidence against: The response timing varies significantly with different payloads

Hypothesis 3: The input validation is partial
- Evidence for: Some payloads get through while others are blocked
- Evidence against: The payloads that get through consistently produce exploitable behavior

After testing {techs}-specific payloads against this {dbType} backend, I'm confident this is Hypothesis 1 — a genuine vulnerability. The key evidence is that I can predictably control the application behavior through the '{param}' parameter.

My exploitation plan:
1. Determine exact injection point and context (is it in a string, numeric, ORDER BY clause, etc.)
2. Identify which data I can access (scope of the vulnerability)
3. Test for write capabilities (can I modify data, not just read it?)
4. Check for escalation potential (from data access to code execution)
5. Document the full attack chain for the report

Estimated severity: The combination of {vulnType} in a production endpoint with access to {impact} suggests this is at least High severity, potentially Critical if I can achieve code execution or access highly sensitive data.`,
];

const EXPLOIT_THINKING_TEMPLATES = [
  `Exploitation of {vulnType} on {domain} is progressing.

Current result: {exploitResult}

This confirms the vulnerability is real and exploitable. Let me think about maximizing the demonstrated impact while staying within scope.

What I've achieved so far:
- Confirmed the injection/bypass works reliably
- Extracted initial data to prove the vulnerability
- The {techs} application is running as {osUser} on the system

Chaining opportunities:
The real power of penetration testing isn't finding individual bugs — it's showing how they chain together. From this {vulnType} finding, I can potentially:
1. {nextSteps}
2. Use any discovered credentials to access other systems
3. Leverage internal network access if I can pivot

Risk-aware exploitation:
I need to be careful here. While I want to demonstrate maximum impact for the report, I also need to:
- Not disrupt the production service
- Not modify or delete any actual data
- Use read-only operations wherever possible
- Log all my activities for the engagement report
- If I get shell access, run only passive enumeration commands (whoami, id, env, cat /etc/passwd)

The goal is to demonstrate that an attacker COULD do severe damage, not to actually cause it. Every exploitation step should be documented with screenshots and command output for the report.

Impact assessment update: This has escalated from a single {vulnType} to a potential full system compromise through exploitation chaining. The severity is Critical.`,

  `The {vulnType} exploit on {domain} worked. Let me analyze what we've gained and plan the next steps.

Exploitation output: {exploitResult}

Current access level analysis:
- I'm running commands as {osUser} which typically has {techs} service-level privileges
- This means I can read application files, environment variables, and potentially database credentials
- The {dbType} database is likely accessible with credentials from the application config

My exploitation methodology is:
1. ENUMERATE: Map what I can access from this position
   - Read /etc/passwd to understand user accounts
   - Check environment variables for hardcoded secrets
   - Read the application configuration files
   - Check network interfaces and routing tables

2. ESCALATE: Look for privilege escalation vectors
   - SUID binaries that can be abused
   - Docker group membership (container escape)
   - Writable cron jobs or systemd timers
   - Kernel version vs known exploits
   - Sudo misconfigurations

3. PIVOT: Identify lateral movement opportunities
   - Internal services reachable from this host: {nextSteps}
   - SSH keys or credentials for other systems
   - Cloud metadata endpoints (if running on cloud infrastructure)

4. EXFILTRATE: Demonstrate data access impact
   - Sample user data to prove access scope
   - Identify PII, PCI, or other regulated data
   - Show what an attacker could steal

I'm going to be methodical about this. Each step builds on the previous one, and every finding goes into the report.`,

  `Excellent — the {vulnType} exploitation on {domain} was successful. Time to think about what this means strategically.

Result: {exploitResult}

As a penetration tester, my job isn't just to pop a shell — it's to demonstrate business risk. Let me think about this from the client's perspective:

Technical impact:
- I've achieved code execution as {osUser} on a {techs} application server
- The {dbType} database likely contains user data, transaction records, or other business-critical information
- From this foothold, the next steps ({nextSteps}) would each represent an escalation of business impact

Business impact translation:
- Data breach: If the database contains PII (which most production databases do), this is a reportable data breach under GDPR, CCPA, and similar regulations
- Financial: Depending on what data I can access, this could include payment information (PCI-DSS scope)
- Reputation: A public disclosure of this vulnerability being exploited would damage customer trust
- Regulatory: Fines and mandatory breach notification costs

I'm documenting every step of the exploitation chain because the client needs to understand not just THAT they're vulnerable, but HOW an attacker would progress through their systems. This attack narrative is what makes the difference between a mediocre pentest report and one that actually drives security improvements.`,
];

// Dedicated templates for network-level failures. These must not reference
// WAFs, input validation, rate limiting, or any application-layer control,
// because the observation (Connection refused, timeout) proves no application
// logic was exercised.
const NETWORK_FAILURE_THINKING_TEMPLATES = [
  `The {whatFailed} step against {domain} could not complete at the network layer.

What I observed: {why}

This is not an application-security signal. The target never received my request in a state where it could respond, so I cannot draw any conclusion about whether the endpoint is vulnerable or not. A "safe" observation here would be wrong; a "vulnerable" observation would be equally wrong.

My plan:
- Treat this attempt as inconclusive and not as a defense success
- Verify whether the host is actually up (different source, different path, general connectivity)
- If the target is genuinely offline, I'll retry after a cool-off window or pivot to other subdomains in scope

What I am NOT concluding:
- I am not attributing this to any protective control on the application side
- I am not concluding that the endpoint is safe — the payload never reached it

Next up: {alternativeApproach}.`,

  `{whatFailed} on {domain} failed at the transport layer. Time to be careful about what that tells me.

Observation: {why}

Analysis:
A connection-level failure is a zero-bit-of-evidence event from the application's perspective. The server process may be down, the port may be closed, a firewall at the network layer may be dropping my source — all three look identical from here. None of them reveal anything about the application's security controls.

What I'll do instead:
1. Check basic reachability with a different path (other subdomain, alternate port)
2. If still unreachable, flag it in the report as "not tested" rather than "not vulnerable"
3. Shift focus to other scoped assets where I can actually run the attack chain

Pivoting to {alternativeApproach}.`,
];

const FAILURE_THINKING_TEMPLATES = [
  `The {whatFailed} approach on {domain} didn't work as expected.

What happened: {why}

This is actually valuable information. Let me analyze why it failed and what that tells me about the target's security:

1. The failure mode suggests {pivotReason}
2. This narrows down what the target IS doing right (credit where due) and where the gaps might be

My pivot strategy:
Instead of pushing harder on the same vector, I should {alternativeApproach}.

Why this alternative might work:
- The current defense seems to be looking for {whatFailed} patterns specifically
- But security is about defense in depth — there might be gaps in adjacent functionality
- The {techs} framework has other common weakness patterns I haven't tested yet

What I've learned from this failure:
- The developers are at least somewhat security-conscious (they've addressed the most obvious attack)
- There's likely a WAF or input validation layer that I need to account for
- I should shift from "loud" scanning to more targeted, manual testing

This is a normal part of a penetration test. Not every attack succeeds on the first try. The skill is in adapting your approach based on what the target tells you through its defensive responses. A good pentester learns as much from failures as from successes.

Let me try the alternative approach now.`,

  `Hmm, {whatFailed} failed on {domain}. Let me step back and reassess.

Failure details: {why}

Root cause analysis:
Looking at this objectively, the failure could mean:
a) The vulnerability doesn't exist here (true negative)
b) The vulnerability exists but my payload/technique was wrong (false negative)
c) There's a security control blocking my specific approach (bypassable)

Given what I know about the {techs} stack, option (b) or (c) is more likely because:
{pivotReason}

My adjusted approach: {alternativeApproach}

What experienced pentesters do differently is they don't give up at the first roadblock. They:
1. Carefully analyze the error/block response for clues about the defense
2. Try the same vulnerability class with different techniques
3. Test adjacent parameters or endpoints that might share vulnerable code
4. Look for inconsistencies in the defensive controls (e.g., POST is filtered but GET isn't)

The key insight is that security controls are rarely perfect. They protect against known patterns, but creative variations or unusual code paths often slip through. That's exactly what we're testing.

Moving to the alternative approach now. If this also fails, I'll document both attempts in the report because it shows the client what their defenses CAN stop — which is valuable information for their security team.`,

  `{whatFailed} was blocked on {domain}. This is interesting — let me think about why.

What I tried: {whatFailed}
What happened: {why}

My analysis:
The fact that this was specifically blocked (rather than just failing silently) tells me:
- The application has active security controls targeting this attack class
- The response behavior reveals what type of filtering is in place
- {pivotReason}

This is a cat-and-mouse situation. The defense is:
- Pattern matching against known attack signatures
- Input validation on specific characters or strings
- WAF rules at the network/application layer

Where defenses typically have gaps:
- Double encoding (URL encode the URL-encoded payload)
- Unicode normalization bypasses
- Multipart form data vs URL-encoded body
- HTTP method switching (GET → POST → PUT)
- Header-based injection (when body is filtered)
- Second-order contexts (inject in one place, trigger in another)
- Timing-based attacks (no visible payload in response)

My next move: {alternativeApproach}

Even if I ultimately can't bypass the control, documenting the attempt helps the client understand their defensive coverage. I'll note in the report: "Tested for {whatFailed} — the following controls were observed: [details]. Bypass attempted via [technique] — [result]."

Good security testing isn't about always finding vulnerabilities. It's about thoroughly testing the controls and honestly reporting what held up and what didn't.`,
];

const POST_EXPLOIT_THINKING_TEMPLATES = [
  `I've established a {accessLevel} foothold on {domain}. Now I need to think strategically about post-exploitation.

Current position:
- Access level: {accessLevel}
- Technology: {techs}
- Database: {dbType}

Post-exploitation objectives (in order of priority):
1. CREDENTIAL HARVESTING: Look for hardcoded credentials, API keys, and tokens
   - Application config files likely contain {dbType} connection strings
   - Environment variables often hold {sensitiveData}
   - Check .bash_history, .ssh/, .aws/ for previous admin activities

2. INTERNAL RECONNAISSANCE: Map the internal network
   - What internal services are reachable? I'll check for {internalServices}
   - Are there other application servers, databases, or management interfaces?
   - Cloud metadata endpoint (169.254.169.254) — if this is a cloud instance, I might get IAM credentials

3. DATA IMPACT ASSESSMENT: What sensitive data can I access?
   - The {dbType} database likely contains: {sensitiveData}
   - I need to quantify the breach — how many records? What sensitivity level?
   - This determines the regulatory impact (GDPR, PCI-DSS, HIPAA)

4. PERSISTENCE EVALUATION (assess only, don't implement):
   - Could an attacker maintain access through reboots?
   - SSH key injection, cron jobs, web shells — I'll document what's POSSIBLE

5. LATERAL MOVEMENT ASSESSMENT:
   - Can I reach other hosts from here?
   - Are there shared credentials or trust relationships?
   - Could I pivot to more sensitive systems?

Every finding here goes into the report as "post-exploitation impact" — showing the client what an attacker would do AFTER the initial compromise. This is often more impactful than the initial vulnerability itself.`,

  `{accessLevel} access achieved on {domain}. Let me think about what this means from an attacker's perspective.

An adversary who reached this point would be thinking about:

1. ESTABLISHING PERSISTENCE — I need to document HOW an attacker would maintain access:
   - Plant an SSH key in authorized_keys (if SSH is available)
   - Create a webshell in a static assets directory
   - Add a cron job for callback
   - Modify an existing application route as a backdoor
   Note: I'll assess these vectors but NOT actually implement them. I'll document the feasibility.

2. MOVING LATERALLY — What else can I reach?
   - Internal services I can see: {internalServices}
   - The {dbType} database server is likely on the same network segment
   - Cloud metadata might give me API credentials for broader access
   - Any internal documentation or wiki might reveal network architecture

3. COVERING TRACKS — A real attacker would:
   - Clear log entries for their commands
   - Modify timestamps on changed files
   - Use existing legitimate processes to blend in
   Note: I'm documenting these techniques so the client's SOC team knows what to look for.

4. DATA STAGING AND EXFILTRATION:
   - Sensitive data accessible: {sensitiveData}
   - An attacker would typically compress and encrypt the data, then exfiltrate via DNS, HTTPS, or cloud storage
   - The absence of DLP controls means data could leave the network undetected

This post-exploitation phase demonstrates the true impact of the initial vulnerability. A SQL injection that "only reads data" becomes a full infrastructure compromise when you follow the attack chain to its logical conclusion.`,
];

const REPORT_THINKING_TEMPLATES = [
  `Time to compile my findings for the {domain} engagement. Let me think about how to present this effectively.

Primary finding: {vulnType} ({severity})
Attack chain: {chainedFindings}
CVSS Vector: {cvssVector}

Report strategy:
I need to translate technical findings into language that resonates with different audiences:

For the CISO/executives:
- Lead with business impact, not technical details
- Quantify the risk: how many user records exposed, what type of data, regulatory implications
- Reference relevant compliance frameworks: {complianceImpact}
- Use risk ratings they understand (Critical/High/Medium/Low)

For the development team:
- Provide exact vulnerable code locations and parameters
- Show the specific payloads that worked (reproducible PoCs)
- Give concrete remediation guidance with code examples
- Reference secure coding standards (OWASP, SANS)

For the security/SOC team:
- Detail the attack indicators they should monitor for
- Suggest detection signatures/rules
- Recommend immediate compensating controls while fixes are developed
- Provide IOCs from the testing

Report quality checklist:
- Every finding has: title, severity, CVSS score, description, reproduction steps, evidence, impact, remediation
- No false positives (everything I report has been confirmed manually)
- Remediation guidance is actionable and specific (not just "fix the bug")
- Executive summary tells the story without technical jargon
- Risk ratings are consistent and defensible

The {vulnType} finding chain ({chainedFindings}) is the centerpiece of this report. I need to show how an initial seemingly-moderate vulnerability escalated to a {severity} issue through chaining.`,

  `Let me organize my findings for the {domain} report.

Assessment summary:
- Main vulnerability: {vulnType}
- Severity: {severity}
- Full chain: {chainedFindings}

CVSS Scoring rationale:
Vector: {cvssVector}
I need to justify each component:
- Attack Vector (AV): Network — exploitable remotely over the internet
- Attack Complexity (AC): Based on whether special conditions are needed
- Privileges Required (PR): What access level is needed to exploit
- User Interaction (UI): Does the attack require a victim to do something?
- Scope (S): Does exploiting this affect resources beyond the vulnerable component?
- CIA Impact: Based on what data/systems were actually accessed

Compliance mapping:
{complianceImpact}
These frameworks are relevant because the client operates in a regulated industry. The findings may trigger mandatory reporting or audit requirements.

Remediation priority:
1. IMMEDIATE (0-48 hours): Patch the {vulnType} vulnerability, rotate any exposed credentials
2. SHORT-TERM (1-2 weeks): Implement compensating controls (WAF rules, rate limiting, additional logging)
3. MEDIUM-TERM (1-3 months): Address root causes (secure coding training, code review process, automated SAST/DAST)
4. LONG-TERM: Establish continuous security testing program, implement defense-in-depth architecture

I'll present the chain {chainedFindings} as a single narrative so the client understands how attackers think and why fixing just one link isn't sufficient.`,
];

// ============================================================
// Evasion & Advanced Technique Thinking Templates
// ============================================================

const EVASION_THINKING_TEMPLATES = [
  `The WAF on {domain} is catching my payloads. Time to think about bypass strategies.

Observed WAF behavior:
- Technology: {techs} stack with what appears to be {alternativeApproach}
- Block pattern: My payloads return {why}
- Timing: Blocks happen within {whatFailed}

WAF bypass techniques I should try:
1. **Encoding chains**: Double URL encode → Unicode normalization → UTF-8 overlong encoding
2. **HTTP method switching**: The WAF may only filter certain methods — try PUT, PATCH, or even CONNECT
3. **Content-Type confusion**: Switch between application/json, application/x-www-form-urlencoded, and multipart/form-data
4. **Chunked Transfer-Encoding**: Break the payload across multiple chunks so the WAF can't reassemble it
5. **Header pollution**: Add duplicate headers or use case variations (Content-Type vs content-type)
6. **Parameter pollution**: Send the same parameter twice — the WAF processes one, the backend processes the other
7. **Null byte injection**: Insert %00 to truncate WAF pattern matching
8. **IP rotation**: If it's IP-based blocking, rotate source through different proxy chains

The key insight is that WAFs and application backends parse HTTP differently. The goal is to craft a request that:
- Looks benign to the WAF's parser
- Gets interpreted as malicious by the application's parser
This parser differential is the fundamental weakness of all WAF-based defenses.

Let me start with encoding-based bypass since it has the highest success rate against {techs} stacks.`,

  `Interesting defense posture on {domain}. I'm being blocked but the block itself is informative.

What the block response tells me:
- Response code: This narrows down the WAF vendor/type
- Error message: {why}
- Timing: {whatFailed}

My evasion playbook for this scenario:
1. **Identify the WAF** — The response fingerprint matches {pivotReason}. Each WAF has known bypasses.
2. **Test edge cases** — Boundary conditions where the WAF regex fails:
   - Very long payloads (buffer overflow in WAF regex engine)
   - Unicode characters that normalize to ASCII injection chars
   - JSON with deeply nested objects that exceed WAF parsing depth
   - Payloads split across multiple HTTP parameters
3. **Timing-based approach** — Even if the response is blocked, timing differences can leak information:
   - If the server processes the payload BEFORE the WAF blocks: timing varies with payload complexity
   - If the WAF is inline: timing is constant regardless of payload
4. **Alternative channels** — Try:
   - WebSocket connections (often bypass WAF entirely)
   - GraphQL mutations instead of REST endpoints
   - File upload functionality for payload delivery
   - Out-of-band techniques (DNS/HTTP callbacks)

The difference between a junior and senior pentester is that a junior gives up when blocked. A senior sees blocks as information and adapts methodically.

Next attempt: {alternativeApproach}`,

  `Multiple attacks blocked on {domain}. Let me reassess from first principles.

Failure log:
- {whatFailed}: {why}
- Defense appears to be: {pivotReason}

Rather than brute-forcing through the front door, let me think about the ARCHITECTURE:
1. Is there a CDN/load balancer I can bypass to hit the origin directly?
2. Are there internal API endpoints accessible through SSRF that skip the WAF?
3. Does the application have WebSocket endpoints? These often lack WAF coverage.
4. Are there legacy API versions (v1) that predate the WAF rules?
5. Can I find the origin IP through DNS history, certificate transparency, or Shodan?
6. Does the cloud infrastructure expose direct paths that bypass the WAF?

The {techs} stack running on {domain} likely has:
- An edge layer (CDN/WAF) that I'm hitting now
- An application layer behind it that may have different parsing rules
- Internal microservices that trust inter-service traffic

If I can bypass the edge layer — through origin IP discovery, alternative protocols, or authorized internal endpoints — the application-layer defenses might be significantly weaker.

This is the "assume breach" mindset: if the front door is locked, check the windows, the back door, the garage, and the doggy door.`,
];

export const ALL_THINKING_TEMPLATES = [
  ...RECON_THINKING_TEMPLATES,
  ...ENUM_THINKING_TEMPLATES,
  ...VULN_THINKING_TEMPLATES,
  ...EXPLOIT_THINKING_TEMPLATES,
  ...FAILURE_THINKING_TEMPLATES,
  ...POST_EXPLOIT_THINKING_TEMPLATES,
  ...REPORT_THINKING_TEMPLATES,
  ...EVASION_THINKING_TEMPLATES,
];
