# Contributing to DeepSight

First off — thanks for being here. DeepSight is a community project and every contribution, from a typo fix to a new detection rule, makes it better for everyone.

This guide will get you from clone to PR as painlessly as possible. If anything here is unclear, [hop into Discord](https://discord.gg/uzWJKDMRY) and ask.

## Code of Conduct

Be kind, be helpful, be human. We're building tools for the community — let's keep it collaborative and low-ego.

## Setting Up Your Dev Environment

```bash
# Clone the repo
git clone https://github.com/R3dy/DeepSight.git
cd DeepSight

# Install dependencies
pip install flask psutil

# Start the dev server
python3 server.py
```

Open `http://localhost:8451` in your browser. You're now running DeepSight locally.

For the docs site:

```bash
# Install docs dependencies
cd docs
npm install

# Start the VitePress dev server
npx vitepress dev
```

### What you need

- **Python 3.8+** with `pip`
- **Linux** — the collector and agent use `/proc` and `/sys`
- **Optional:** `psutil` for richer metrics (the agent falls back to `/proc` parsing without it)
- **Optional:** `inotify_simple` for file integrity monitoring

## Code Style

We keep things simple because DeepSight is a small, focused codebase:

- **Python:** Follow PEP 8. Use meaningful variable names. The collector is a single `server.py` — keep it that way unless there's a compelling reason to split things out.
- **JavaScript:** Vanilla JS in `static/index.html`. No framework. No build step. Keep it readable and avoid large dependencies.
- **Comments:** Explain the "why", not the "what". Complex logic (like the C2 beaconing periodicity analysis) benefits from inline comments.
- **Commits:** Write clear, present-tense messages. `Add DNS entropy scoring for DGA detection` is better than `added feature`.

## Pull Request Process

1. **Fork the repo** and create a feature branch from `main`.
2. **Make your changes.** Keep them focused — one feature or fix per PR.
3. **Test it.** Run the collector locally and verify your changes work. For UI changes, check both the Detail and Overview views.
4. **Open a PR.** Include:
   - What you changed and why
   - How to test it
   - Screenshots or logs if relevant (especially for UI or detection changes)
5. **Wait for review.** We'll get to it as quickly as we can — usually within a couple of days. If it's been longer, give us a nudge on Discord.

### What makes a good PR?

- **Focused scope.** One feature, one fix, one improvement. No drive-by refactors.
- **Tested.** You've verified it works on your own machine.
- **Respectful of the existing design.** DeepSight is intentionally simple — no framework, no database for metrics, no build step. If your change adds significant complexity, explain why it's worth it.

## Where to Discuss

- **🐛 Bugs & feature requests:** [GitHub Issues](https://github.com/R3dy/DeepSight/issues)
- **💬 Chat & questions:** [Discord](https://discord.gg/uzWJKDMRY)

## Types of Contributions

Here are some ways to help, ordered from easiest to most involved:

| Level | What | Example |
|-------|------|---------|
| 🟢 Easy | Docs fixes, typos, clarifying examples | Fix a broken link in the API reference |
| 🟢 Easy | Detection rule ideas | Suggest a new regex pattern for spotting suspicious processes |
| 🟡 Medium | UI improvements | Add a new widget or improve mobile responsiveness |
| 🟡 Medium | New API endpoint | Expose a new data source the community would find useful |
| 🔴 Hard | Agent improvements | Add GPU reporting to the agent, or packaging for non-systemd init systems |
| 🔴 Hard | Architecture changes | Federation, persistent metrics, alert notifications |

If you're unsure where to start, [ask on Discord](https://discord.gg/uzWJKDMRY) — we'll point you at a good first issue.

---

**One more thing:** this project was vibe-coded with AI assistance. That means some things might be a little quirky, and documentation might occasionally lag behind code. If you spot something that doesn't make sense, it's probably not you — it's us. Open an issue or PR and help us make it better.
