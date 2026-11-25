# Automation

| Workflow | Trigger | Runner and permissions |
| --- | --- | --- |
| `release.yml` | Push to `main` or manual dispatch | GitHub-hosted Ubuntu. Read-only collection, Pages-only deployment and a separate archive job. |
| `engineering.yml` | Manual dispatch | GitHub-hosted Ubuntu. Read-only candidate and independent reproduction, then a constrained promotion job. |

A push to `main` queues a GitHub Pages deployment. The new release goes live after collection and validation succeed. Manual releases use the same workflow.

```text
gh workflow run release.yml --ref main
gh workflow run engineering.yml --ref main
gh run list --workflow release.yml
```

The publishing workflow uses the publication branch for record revisions. It also imports reviewed canonical records from the source branch when their IDs are new to the publication branch. This preserves the first collection for a new publisher even if its feed rotates during review. Source failures preserve accepted data and reduce freshness. Same-day duplicate runs retain the current snapshot. Workflow summaries record the run outcome even when the site remains on the previous release.

The engineering lane optimizes the generated halftone asset losslessly when the unoptimized source is present. It verifies the pixel values and reduced size, rerenders its candidate under a separate runner and grants write access only for the exact reproduced path set. A reviewed asset promotion uses a manual release dispatch because pushes made with the GitHub Actions token do not trigger another workflow. A failed deployment triggers a source revert if the main branch still permits a fast-forward. This workflow does not submit source text to agents or widen its own authority.

Local Codex CLI 0.152.1 was signed in through ChatGPT. The CI runners use the GitHub Actions token and no personal Codex credentials. The current engine is deterministic with zero model requests, zero tokens and a zero USD daily/monthly AI budget. A separately authorized provider and server-side budget reservation are needed to activate model-assisted generation or broaden engineering scope.
