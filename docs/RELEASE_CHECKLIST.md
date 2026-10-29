# SpecterLAN release checklist

Run from the repository root on Windows. Check a box only after observing the
result; automated tests are not a substitute for a live scan/model rehearsal.

## Automated verification

- [ ] `python -m pytest -q` passes in the selected environment.
- [ ] `python -m ruff check .` passes.
- [ ] `git diff --check` passes.
- [ ] Fresh environment install succeeds, without changing the main environment:

  ```powershell
  python -m venv .venv-release
  .\.venv-release\Scripts\python.exe -m pip install -e ".[dev]"
  .\.venv-release\Scripts\python.exe -m pip check
  .\.venv-release\Scripts\python.exe -m pytest -q
  .\.venv-release\Scripts\python.exe -m ruff check .
  ```

- [ ] A wheel installs/imports outside the checkout and includes `specterlan/style.css`.
      The runnable UI is distributed as a source checkout, not a wheel entry point.
- [ ] README local links and screenshots resolve; Mermaid renders on GitHub.

## Manual runtime checks

- [ ] `ollama list` includes `gemma3:4b` (or the configured local model).
- [ ] Model is warmed and a real Ask the Ghost request succeeds.
- [ ] Live scan on an owned/administered network succeeds; verify sidebar subnet.
- [ ] Nmap host discovery works where installed; fallback works when unavailable.
- [ ] Device labels persist; the same MAC keeps identity across an IP change.
- [ ] Restart preserves live history; existing databases migrate without lost snapshots.
- [ ] Demo stages show baseline, new/unreviewed ESP, TV IP move, vanished phone.
- [ ] Reset Demo replays cleanly without changing live history or metadata.
- [ ] Ask the Ghost works on Demo evidence; cited facts match the explanation.
- [ ] Ollama offline/missing model errors leave scanning and history available.
- [ ] UI remains readable at laptop width; screenshots show simulated data only.

## Repository and privacy

- [x] MIT license selected; LICENSE, README, package metadata, and submission wording aligned.
- [ ] Review tracked files and history for secrets, credentials, private inventories,
      local paths, generated SQLite databases/sidecars, and temporary artifacts.
- [ ] `.gitignore` excludes environments, caches, metadata, databases, and `.env` variants.
- [ ] Keep `.env.example` (non-secret reference) and the two curated demo screenshots.
- [ ] Keep server logs, real-network screenshots, and recordings with private details out of Git.
- [ ] Product name is SpecterLAN; repository name remains `spectarlan`.
- [ ] Confirm origin: `https://github.com/rishabh-hasija/spectarlan.git`.
- [ ] Review all changes; Git status is clean after the maintainer's authorized commit.
      Milestone hardening does not authorize an automatic commit or push.
- [ ] Confirm the GitHub repository is public before sharing it with judges.

## Submission

- [ ] Record the [60-second demo](../README.md#60-second-demo-sequence).
- [ ] Replace the video placeholder in [submission text](HACKTOBERFEST_SUBMISSION.md).
- [ ] Submission text is accurate, personalized, and reviewed; disclose AI assistance.
- [ ] Use the official template/tag and check challenge eligibility/build window.
- [ ] Confirm the deadline with organizers: the event API timestamp and prose
      deadline currently differ; plan for the earlier cutoff until clarified.
- [ ] Publish/submit only after the maintainer explicitly authorizes it.

Model limitations, missing-MAC identity limitations, platform differences, and
safety boundaries are documented in the [README](../README.md) and
[behavior reference](BEHAVIOR.md). Keep unresolved checks visible at release.
