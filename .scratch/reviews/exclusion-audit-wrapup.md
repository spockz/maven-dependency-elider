<!-- WHY: Bundles tool-quality and runtime evidence across the exclusion-audit implementation slices. -->
# Exclusion-audit track wrap-up

- **Semantic-tool QoL:** Unknown; no semantic tool was used in the retained R4 work.
- **Built-in comparison:** The resolver-semantics review used `rg`, targeted source reads, Git diffs, and `javap`; the session-isolation work used `rg` and `apply_patch`. No comparative speed or outcome data was retained.
- **Runtime:** Focused tests 24.1s, `make lint-java` 26.2s, and `make test-plugin` 4m28s for the Elide ban-enforcement slice. Resolver/session review runtimes were not recorded.
- **Manual source-edit fallback:** None reported by the resolver/session work. The Elide implementer removed two temporary test files after consolidating their fixture.
- **Suboptimal tool:** One default-sandbox read-only inspection hit a `bwrap` capability error; approved escalated reads worked. The policy-contract worker independently reported a blocked PMD inspection and made no edits for it.
