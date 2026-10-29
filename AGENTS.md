<!-- This file sets repository-wide agent guidance so local implementation and documentation changes follow the project's released-format version policy. -->
# Repository Agent Instructions

## Persisted formats and protocols

- Keep plugin release versions separate from schema or protocol versions for persisted data.
- While a format has not been published in a `maven-dependency-elider` release, evolve it without incrementing its schema or protocol version. Keep each current unreleased format at version 1.
- Once a released format is changed, increment that format's version before releasing the change. Version each persisted format independently.
- Do not add compatibility aliases or migrations for unreleased draft formats. Reject malformed or incompatible payloads explicitly.
- Update the format's writer, reader, validator, fixtures, and documentation together. Document any compatibility or migration promise in an ADR before making it.

## Tooling and implementation languages

- Do not use Python or Node.js in this project.
- Tooling should stick to shell when simple and orchestrating commands, be implemented as part of Java unit/integration tests, or be built as a Go program.
- Tooling such as applicable Java versions can be found in `.scratch/toolchains` of the main clone/worktree.

## Generated command examples

- When a change affects an example fixture, its documented Maven command, or the output shown in README or plugin usage, refresh the generated examples with `make update-transcripts` (`go run scripts/update-transcripts.go --update`) before wrapping up.
- Review and include the generated documentation changes. Do not hand-edit content inside transcript marker blocks; update the manifest or fixture setup, then regenerate with `make update-transcripts`.
- Use `make check-transcripts` to check for drift without rewriting documentation.
