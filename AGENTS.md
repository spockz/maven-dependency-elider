<!-- This file sets repository-wide agent guidance so local implementation and documentation changes follow the project's released-format version policy. -->
# Repository Agent Instructions

## Persisted formats and protocols

- Keep plugin release versions separate from schema or protocol versions for persisted data.
- While a format has not been published in a `maven-dependency-elider` release, evolve it without incrementing its schema or protocol version. Keep each current unreleased format at version 1.
- Once a released format is changed, increment that format's version before releasing the change. Version each persisted format independently.
- Do not add compatibility aliases or migrations for unreleased draft formats. Reject malformed or incompatible payloads explicitly.
- Update the format's writer, reader, validator, fixtures, and documentation together. Document any compatibility or migration promise in an ADR before making it.
