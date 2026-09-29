# SETUP.md — what to install and how to start with Claude Code in VS Code

## 0. Limit Docker memory first (Windows/WSL2)
Create `C:\Users\<you>\.wslconfig`:
```
[wsl2]
memory=10GB
processors=6
swap=8GB
```
Then run `wsl --shutdown` in PowerShell and restart Docker Desktop. Use compose profiles; never run every service at once.

## 1. Install (tick these off first)
| Tool | Why | Check |
|---|---|---|
| Docker Desktop (with Compose v2) | Kafka, Redis, Postgres, lab network | `docker compose version` |
| Python 3.11+ | Detection, ML, generator | `python --version` |
| Git + GitHub account | Repo and CI | `git --version` |
| Node.js 18+ | Claude Code CLI | `node --version` |
| Java 21 + Maven | Spring Boot gateway and target-shop | `java --version` |
| Claude Code | The builder | `claude --version` |
| Nmap, Wireshark (tshark) | Attack lab and pcap validation | `nmap --version` |
| sqlmap, Hydra, OWASP ZAP | Attack lab (lab-only) | install with Phase 2 |
| Burp Suite Community | Manual testing + screenshots | install with Phase 2 |
| Splunk Free (Docker image) | HEC forwarding | Phase 3 |
| kind, kubectl, Terraform | K8s + IaC | Phase 6 |
| Anthropic API key or Azure OpenAI key | LLM triage agent | Phase 5 (put in .env) |

Claude Code install: `npm install -g @anthropic-ai/claude-code`, then run `claude` inside the project folder and log in with your Claude Pro account. If the install command has changed, check the current Claude Code docs.

## 2. VS Code extensions
- Claude Code (Anthropic) — the VS Code integration
- Python + Pylance
- Ruff
- Docker
- YAML (Red Hat)
- Extension Pack for Java (only when you reach Phase 2)
- GitHub Pull Requests and Issues (optional)
- Mermaid Preview (for README diagrams)

## 3. Get the data (do this while Docker images download)
1. Download **CIC-IDS2017** (MachineLearningCVE CSVs) from the University of New Brunswick CIC website.
2. Put the CSVs in `data/` (already gitignored).
3. If the download is slow or blocked, use **UNSW-NB15** instead and tell Claude Code to adapt `train.py`.
4. You do not need all files. A stratified 200,000-row sample is enough.

## 4. Project start
```bash
mkdir sentinel && cd sentinel
git init
# copy in: CLAUDE.md  PRD.md  README.md  TASKS.md  SETUP.md
code .
claude
```

## 5. First prompt to paste into Claude Code
```
Read CLAUDE.md, PRD.md and TASKS.md fully. Summarize the plan back to me in 10 lines,
list any risks or ambiguities, then begin Task 1 from TASKS.md. Follow the hard rules in CLAUDE.md:
never invent metrics, only document what exists, lab-only attacks, no secrets in git.
After each task, run tests and show me the output before moving on.
```

## 6. Suggested Claude Code workflow tonight
1. Plan mode first for Tasks 1 and 4 (infra and ML), so it proposes before it edits.
2. One task per session segment; commit after each (`git add -A && git commit -m "feat: ..."`).
3. If a step fails, paste the error and ask: "Diagnose the root cause before changing code."
4. If context gets long, run `/compact`, or start a fresh session with: "Read CLAUDE.md, we are on task N."
5. Push to GitHub early and often (public repo, MIT license).

## 7. Order of work
Follow TASKS.md T1 to T24 in order. Each phase leaves a working system, so if you run out of time the repo is always in a runnable state.
Rough effort: Phase 1 about 4 to 5 hours, Phase 2 about 4 hours, Phases 3 to 6 about 2 to 3 days total.
For tomorrow's 2 PM registration deadline, put on the resume only what is running by then, and keep updating the resume as later phases land.

## 8. Before each resume update
- Numbers come from `results/metrics.json`, test counts, and CI reports.
- The title-line tech stack lists only technologies already in the repo.
- Be ready to explain labels vs features, why you split before scaling, what the false positives were, and dataset limits.
