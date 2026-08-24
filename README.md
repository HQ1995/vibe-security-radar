# Vibe Security Radar

A [Georgia Tech SSLab](https://gts3.org/) catalog of public vulnerabilities whose root cause traces to AI-written code.

**https://vibesecradar.com/**

We start from disclosed GHSA and CVE advisories, not from a scan of every AI commit. A finding is published only when we can show three things on the same attack path: the AI-authored change, the vulnerable behavior, and the fix that closed it. Cursor, Copilot, Claude Code, and similar tools all appear; the catalog is about the code they left behind, not a ranking of tools.

There are 195 such findings in the 2025-05 – 2026-08 window. That is a lower bound, not a census of every AI bug. Many AI-assisted changes never become a public advisory, and some that do leave a history we cannot recover.

## How a case gets in

1. **Match the advisory.** Confirm the GHSA or CVE, the repository, the package, and the actual vulnerability — not a neighboring bug in the same project.
2. **Find the AI change.** Bind an AI authorship signal (commit trailer, co-author, agent transcript, or equivalent) to the exact commit and the hunk that matters.
3. **Prove cause and fix.** Compare the parent, the AI change, and the minimum security fix. The AI code has to affect the same mechanism the patch later closes. An AI marker on a nearby commit is not enough.
4. **Confirm the release.** Record the vulnerable and fixed versions when the advisory states them, and fold true duplicates so one GHSA is one case.

What counts: AI introduced the flaw, exposed the vulnerable path, or left a security fix incomplete.

What does not: an AI marker, git blame, or model verdict on its own. We also do not claim that AI is riskier than human code. This dataset is not a rate comparison.

The longer writeup is on the site: [How we verify](https://vibesecradar.com/about).

## Contact

A case looks wrong, or we missed one: [open an issue](https://github.com/HQ1995/vibe-security-radar/issues) or email hanqing@gatech.edu.

## License

MIT
