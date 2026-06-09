# Implementation Audit Trail

One doc per completed task: `Phase-<N>-Task-<M>-<slug>.md`.

Each doc records **what was built, how it was tested, and what Codex found** —
the evidence behind checking a box in `docs/tasks.md`. Committed in the same
commit as the task it documents.

## Convention

- Filename: `Phase-<N>-Task-<M>-<slug>.md` (e.g. `Phase-3-Task-13-health-checker.md`).
- `<N>` = phase number from `docs/tasks.md`, `<M>` = task number, `<slug>` =
  short kebab-case summary.
- Major design decisions / accepted limitations get their own
  `docs/audit/NNN-*.md` doc and are linked from here.

## Template

```markdown
# Phase <N> · Task <M> — <title>

**Status:** complete
**Commit:** <filled at commit time>
**Files:** <source files touched>

## What
<1-3 sentences: what this task implemented.>

## How tested
- Build: `make build` / `make generate` result.
- Unit: which tests, pass/fail counts.
- Live (EKS): node, method (cross-compiled test binary in privileged pod, etc.),
  and the actual evidence (test output, bpftool output, metric values).
- If not live-testable: why (pure logic), and what unit coverage substitutes.

## Codex review
- Rounds: N.
- Findings (severity — summary — resolution). Note any finding dismissed as a
  Codex hallucination, with the source line that disproves it.
- Final: clean / outstanding.

## Decisions
- Links to `docs/audit/NNN-*.md` for any major decision, or "none".
```
