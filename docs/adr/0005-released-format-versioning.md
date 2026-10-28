<!-- This ADR records when persisted format versions change so drafts do not accumulate meaningless version history before a release establishes compatibility obligations. -->
# ADR-0005: Versioning Released Persisted Formats

- Status: Accepted
- Date: 2026-10-28

## Context

The plugin stores several independent formats, including resolver plans, captured resolver graphs, class-usage data, elision reports, and output-cache metadata. These are schema or protocol versions, not plugin release versions. Before a format has shipped in a `maven-dependency-elider` release, its representation may still change without creating a compatibility obligation. Incrementing version numbers for those unreleased edits suggests a migration history and compatibility promise that do not exist.

## Decision

- Keep every unreleased persisted format at schema version 1 while its representation evolves.
- A change to a format that was previously published in a `maven-dependency-elider` release increments that format's schema or protocol version before the changed format is released.
- Version each persisted format independently. A change to one format does not increment unrelated format versions or the plugin release version.
- Do not promise compatibility aliases or migrations for unreleased formats. Readers reject malformed or incompatible payloads explicitly.
- Before making a compatibility or migration promise for a released format, record its scope and policy in an ADR.

## Consequences

Unreleased formats can be simplified without preserving draft versions. Once a release publishes a format, changing it requires a version increment for that format and an explicit decision about how consumers handle the published representation. Writers, readers, validators, fixtures, and documentation must change together.
