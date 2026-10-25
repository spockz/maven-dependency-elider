<!-- WHY: Preserves observed tooling outcomes and their evidence limits across sessions, without inventing semantic-tool comparisons for workflows that did not use them. -->
# Tooling Assessments

## 2026-10-25: Initial implementation session closeout

The local transcript extractor inspected 39 retained root/child logs for thread `01a16e75-660f-7af0-9a43-22a9197c36f9`. It found zero executed semantic operations, zero semantic results, and four command-review candidates. Manual inspection identifies those candidates as shell downloads of repository settings or documentation mentioning semantic tools, not executed semantic operations. There were no missing referenced child logs in that extraction; historical completeness outside retained logs remains unknown.

| Workflow | Observed outcome | Agent efficiency and runtime comparison |
| :--- | :--- | :--- |
| Repository-native search, patching, formatting, and checks | Sufficient for the implemented slices. Independent review caught weak tests and the missing negative compiler-classpath proof; corrected checks passed. | No semantic workflow was executed, so comparative efficiency and semantic/built-in runtime ratios are unavailable. Historical per-agent wall-clock totals were not captured. |
| Sandbox shell execution | A read-only repository command failed before execution with `bwrap: Unexpected capabilities but not setuid, old file caps config?`. Auto-reviewed escalation allowed repository commands to run. No repository mutation resulted from the failed attempt. | Environment failure; cause beyond the reported sandbox error is unknown. Retry overhead was observed but not measured as a complete workflow. |
| App terminal access | `codex_app.read_thread_terminal` returned `No handler registered`. Shell inspection supplied repository state. | Capability unavailable in this runtime; no equivalent terminal-history timing comparison was measured. |
| Documentation verification | Markdown lint found one trailing blank-line issue in RQ-0005. Its configured mechanical fix resolved it; the full Markdown check passed. | Normal validation/fix cycle, not a semantic-tool defect. |

The extractor output is `.scratch/closeout-semantic-calls.json`; track receipts are bundled in `.scratch/closeout-review-evidence.tar.gz`. The final integration checks and their measured elapsed times are recorded in the [session handover](handovers/2026-10-25-session-closeout.md) and `.scratch/closeout-verification.json`. Those build measurements are not a semantic-tool benchmark. No token savings, runtime savings, or exhaustive coverage of unavailable history is claimed.
