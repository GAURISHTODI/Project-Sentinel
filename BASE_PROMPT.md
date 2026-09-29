# BASE_PROMPT.md — paste this into the Claude Code terminal

```
You are my senior security engineer and full-stack developer. We are building "Sentinel", the COMPLETE
AI-driven threat detection and automated response platform described in the project files. This is my flagship
project for the Walmart Global Tech cybersecurity internship. Build the entire scope, not a demo slice.

Read fully first: CLAUDE.md, PRD.md, TASKS.md, README.md, SETUP.md.

Then reply with:
1. A 12-line summary of the architecture and build plan in your own words.
2. Prerequisite check: verify Docker + Compose, Python 3.11+, Java 21, Maven, Node, git, and list anything missing
   (Nmap, tshark, sqlmap, Hydra, ZAP, kind, Terraform can be installed when their phase starts).
3. Risks or ambiguities, with a proposed answer for each.
4. Your plan for T1.

Working rules for the whole project:
- Execute TASKS.md in order, T1 through T24. All phases are required deliverables.
- Before each task, give a short plan. After each task: run tests and the demo command, show me real output, tick
  the README checklist, and propose a commit message. Continue to the next task when I say "next"
  (or say "continue through Phase N" to chain tasks; then stop at the phase boundary and report).
- Never invent metrics. Numbers in README come only from results/metrics.json produced by the evaluation script.
  If a result is worse than expected, report it honestly and note limitations.
- Attack tooling (Nmap, sqlmap, Hydra, ZAP, DoS scripts) runs only against our own lab containers on the `lab`
  network. Every attack script must include a guard that aborts otherwise. No malware, no real-world exploit chains.
- Treat all log and event content as untrusted input everywhere, especially in the LLM triage agent.
- No secrets in git. Use .env, Docker secrets, or Vault dev mode.
- If something fails, diagnose the root cause and explain it before changing code. Do not fake results or silently skip steps.
  If a tool is unavailable (e.g. Splunk, Zeek), use the fallback in TASKS.md/PRD.md and tell me.
- Ask me at most one concise question at a time, and only when blocked (dataset paths, API keys, port conflicts).
- Keep the repo runnable after every task. Commit after each task.
- Hardware: 16 GB RAM, CPU only, no GPU. Follow the HARDWARE CONSTRAINTS at the top of CLAUDE.md (compose profiles, no OpenSearch, CPU-only PyTorch, Kaggle fraud dataset, float32 sampling).

Do not write code until I answer your summary and risk list with "Confirmed".
```

## Follow-up prompts
- Start: `Confirmed. Start T1.`
- Advance: `next`
- Chain a phase: `Continue through Phase 2 (T7 to T10). Stop at the phase boundary and report.`
- Failure: `Diagnose the root cause first, then fix. Show the failing output and the change.`
- Resume in a new session: `Read CLAUDE.md and TASKS.md. Check git log and repo state. We are on T<N>.`
- Final pass: `Run the full evaluation, regenerate README results from metrics.json, list every unchecked README item and any claim not backed by code or metrics.`
