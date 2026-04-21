# Integrating the Fine-Tuned Qwen into AOS

## 1. What the dataset actually teaches

The 8,084 training entries encode **four skills simultaneously**, each trained by a specific structural pattern in the data:

| Skill | How it's encoded | What the model will do |
|---|---|---|
| **Tool-call emission** | `<tool_call>{"name": ..., "arguments": ...}</tool_call>` after every intent turn | Emit parseable JSON tool calls the orchestrator can dispatch |
| **Causal reasoning** | Intent → call → observation → grounded analysis sequence, never reversed | Wait for observation before drawing conclusions; reason from actual output, not assumptions |
| **Failure recovery** | Observation-aware thinking routes by `unreachable` / `timeout` / `blocked` / `ratelimited` class | Classify why a tool failed and pivot instead of hallucinating success |
| **Structured reporting** | 88.8% of entries end in CVSS + CWE + evidence PoC + remediation; 11.5% end in a short triage verdict | Produce either a full pentest report OR a quick go/no-go call, based on task framing |

Not trained:
- Active Directory, Windows privesc, mobile/iOS, binary/reverse, LLM/prompt-injection, cloud beyond AWS S3
- Tool *execution* — the model emits commands, it does not shell out
- Novel exploit invention — reasoning is varied-templated, not inventive

## 2. Expected model behavior in production

When you prompt a deployed fine-tuned Qwen 3 8B abliterated with the same ChatML template used in training:

```
system: [pentester persona + available tools list]
user:   Do a pentest on api.acme.com — focus on A03 injection.

A: <think>Working hypothesis: the /search endpoint is likely vulnerable because
             error responses suggest unsanitized input reaches the backend...</think>
            Let me kick off enumeration with ffuf to map the attack surface.
            <tool_call>{"name":"ffuf","arguments":{"url":"https://api.acme.com/FUZZ",...}}</tool_call>

observation: [ffuf] Output: /api/v1/search [200] 1823 bytes ...

A: <think>ffuf returned a 200 on /api/v1/search with a reflected parameter.
             This matches my hypothesis — testing with sqlmap next.</think>
            Looking at the `ffuf` output, the signal I was looking for is present.
            Based on the reflected response, the `search` endpoint is the right
            next target. Running sqlmap to confirm the injection vector.
            <tool_call>{"name":"sqlmap","arguments":{...}}</tool_call>
            ...
```

### Concrete behavioral traits you'll see

| Trait | Frequency in training | Implication for AOS |
|---|---|---|
| Emits inline `<think>` | 63% of entries | Plan on CoT parsing; 37% of responses will be direct action |
| Emits `<tool_call>` | 100% of entries | Every "action" response is dispatchable |
| Names the tool it just ran in analysis | 100% of post-observation turns | Audit trails are auto-generated |
| Produces full CVSS report at end | 88.8% | Handles the reporting phase without extra prompting |
| Produces a brief triage verdict | 11.5% | Reliably handles "quick check" prompts |
| Hallucinates findings before tool ran | ~0% | Safe to chain tools without guard-railing output |
| Claims success when tool connection-refused | ~0% | Won't fabricate results on infrastructure failure |
| Refuses offensive-security prompts | near-zero (abliterated base) | No safety friction in-scope; **external authorization checks are your responsibility** |

## 3. Where it fits in AOS architecture

The model is a **reasoning + narration core**. It does not execute. Your AOS provides everything around it:

```
┌─────────────────────────────────────────────────────────────────┐
│                         AOS Orchestrator                        │
│                                                                 │
│  ┌──────────┐   ┌─────────────────┐   ┌────────────────────┐   │
│  │ Scope    │   │ Fine-tuned Qwen │   │ Tool Executor       │   │
│  │ & Authz  │──▶│ (inference)     │──▶│ (nmap, sqlmap, ...) │   │
│  │ (AOS)    │   │                 │   │ (sandboxed)         │   │
│  └──────────┘   └─────────────────┘   └────────────────────┘   │
│        ▲                 │                      │              │
│        │                 │ <tool_call>          │ real stdout  │
│        │                 ▼                      ▼              │
│   user intent     ┌──────────────────────────────────┐         │
│                   │ Session state + conversation log  │         │
│                   └──────────────────────────────────┘         │
│                                                                 │
│  ┌──────────────┐   ┌──────────────┐   ┌─────────────────┐    │
│  │ Eval harness │   │ Report store │   │ Kill-switch/HITL │    │
│  │ (regression) │   │ (artifacts)  │   │ (critical gates) │    │
│  └──────────────┘   └──────────────┘   └─────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
```

### Division of responsibility

| Layer | Owner | Why |
|---|---|---|
| Authorization / scope enforcement | **AOS** | Model is abliterated — it will comply with any target |
| Tool dispatch & sandbox | **AOS** | Model emits intent strings, not syscalls |
| Rate limiting, network egress control | **AOS** | Model has no concept of budget or legality |
| Reasoning, tool selection, next step | **Model** | What it was trained for |
| Analysis of tool output | **Model** | Observation-grounded |
| Report synthesis | **Model** | CVSS + CWE + remediation built-in |
| Regression testing post-deploy | **AOS + eval-harness** | Detects drift |

## 4. Prompts that work well

Prompt shape matters — the model is tuned to *specific framings* seen in training.

### High-fit prompt patterns

| Pattern | Example | Why it works |
|---|---|---|
| **Full authorized engagement** | "I have authorization to test acme-corp.com. Start with OSINT, then move to active enumeration. Target context: Node.js/Express/MongoDB." | Matches `USER_PROMPTS_INITIAL` format |
| **Triage/go-no-go** | "Quick triage on api.acme.com — is the IDOR issue worth a deeper look?" | Matches the 11.5% triage slice |
| **Contextual follow-up** | "Based on the 403 you just saw on /admin, try header injection to bypass." | Matches the 60% contextual-followup prompts |
| **Evasion pivot** | "The WAF blocked your payload — try alternative techniques." | Matches `USER_PROMPTS_EVASION` |
| **Deep analysis** | "Explain the attack chain and impact in depth." | Matches `USER_PROMPTS_DEEP_ANALYSIS` |
| **Report request** | "Write up the finding with CVSS, evidence, and remediation." | Matches the final-turn structure |

### Target-context format that helps

The model was fed `Target context: {desc}\nTechnology: {techs} with {db} database` — including those fields primes better tool selection:

```
Target context: staging.acme.com, Node.js/Express API with JWT auth
Technology: Node.js/Express/PM2 with MongoDB database
```

## 5. Prompts that won't work well

| Prompt type | Why it fails | Observable failure mode |
|---|---|---|
| **Outside domain** (AD, Windows, mobile, binary) | Zero training signal | Will confabulate web-attack tools against non-web targets |
| **Non-security tasks** ("write a poem") | Model locked into pentester identity via system prompt | Will pivot back to pentesting framing |
| **Asking the model to execute** ("run nmap and show me") | Model emits the *call*, not the result | Returns a `<tool_call>` waiting for observation |
| **Single-turn chat without observation feedback** | Model expects tool loop | Will stall or invent plausible-sounding output |
| **Tool output not formatted as `observation` role** | Breaks the ChatML template | Model may hallucinate or misattribute |
| **Scope-violating requests** | No refusal trained | **Model will comply — AOS must enforce scope externally** |
| **Novel zero-day invention** | Trained on template-composed reasoning | Produces convincing-sounding but derivative analyses |

## 6. Integration recommendations

### System prompt template
Mirror what was trained. Minimally:

```
You are PentesterFlow, an expert offensive security AI assistant specialized in
web application penetration testing, API security assessment, and bug bounty
hunting. You operate as an enterprise-grade penetration tester with deep
knowledge of OWASP Top 10, API Security Top 10, modern web attacks, auth
bypass, and cloud misconfiguration.

You have access to the following tools: {tool_list_with_descriptions}

You think methodically in <think> blocks, emit tool calls as
<tool_call>{"name": ..., "arguments": ...}</tool_call>, wait for observations,
then analyze results before deciding next steps.
```

Keep the tool list in the system prompt — training conditioned the model on seeing it there.

### Inference config (Qwen 3 native template, after GGUF quantization)

```
temperature: 0.6     # trained range; higher = more invention, lower = repetition
top_p: 0.9
max_tokens: 4096     # full responses with <think> need headroom
stop: ["<|im_end|>"]
```

### Agent loop pseudocode

```python
while task_incomplete:
    output = qwen.generate(messages)
    thinking, body, tool_calls = parse(output)
    log(thinking)  # audit, don't show user
    display(body)

    if not tool_calls:
        break  # final turn

    for tc in tool_calls:
        if not scope_allows(tc):        # AOS enforcement
            raise ScopeViolation(tc)
        result = aos_executor.run(tc)    # real shell
        messages.append(observation(result))
```

### Regression testing
Keep `scripts/eval-harness.mjs` in CI. After every fine-tune iteration or model update, run it against a small sample of fresh agent traces. The three checks (foreign tool mention, obs/think mismatch, scenario coverage) catch behavior drift before users see it.

## 7. Honest limitations you must design around in AOS

1. **Not a planner, a reactor.** It's good at "given this observation, what's next" — less good at "plan the whole engagement." AOS should decompose the engagement into scenario chunks it recognizes.

2. **Hallucination risk on unfamiliar observations.** If a tool returns output unlike anything in training (e.g., a Burp Suite XML dump), the model will improvise. Normalize tool output into shapes the model saw in training.

3. **Top 4 tools = 62% of trained calls.** The model has a prior for `httpx, curl, python_script, nuclei`. Other tools work but may get picked less often than ideal. Compensate by explicitly recommending them in the user prompt or system prompt.

4. **Abliterated base = no built-in safety.** It will write working exploits against targets you don't own if you don't stop it at the orchestrator layer. This is a feature if your AOS has a strong scope/authorization layer; a liability if it doesn't.

5. **Single-agent model.** No native multi-agent / handoff behavior. If AOS uses multiple specialized agents, each one needs its own system prompt context and you shouldn't expect the model to delegate.

6. **No long-horizon memory in the model.** Context window only. Long engagements need AOS to summarize past sessions into the prompt.

7. **Scenario coverage is OWASP + modern web + API.** Calling it a "general pentest assistant" overstates. For AD, mobile, binary, LLM security, etc., you need additional data or a different model.

## 8. TL;DR for AOS integration

| Question | Answer |
|---|---|
| What does the model do best? | Multi-turn web/API pentest flows, producing tool calls + CVSS reports |
| What does AOS provide? | Scope enforcement, tool execution, sandbox, session state, authorization |
| Best prompt shape? | Authorized engagement + target context + tech stack; let the model pick tools |
| Worst prompt shape? | Non-web targets, ad-hoc chat, requests expecting the model to execute |
| Safety model? | **External.** Model has no refusal. AOS owns the gate. |
| When to use triage vs full? | Triage for "quick go/no-go" prompts; full engagement otherwise. Phrase the prompt to match. |
| How to spot drift? | `eval-harness.mjs` on production traces |

Treat the fine-tune as a **well-trained junior pentester with good format discipline and no judgment about legality**. AOS is the senior engineer who decides what gets attempted, and the hands that actually run the tools.
