<!-- WHY: Records review and verification evidence for the AC12 core checkpoint. -->

# WP-VEX-02-TYPED Slice 4A Review Receipt

## Scope

Core-only AC12 checkpoint: immutable producer identity rules and a strict schema-v1 local vulnerability-cache envelope around the existing advisory document. Upstream OSV input, bundled seed formats, production cache loading, installed plugin identity resolution, and trimmed-output cache integration are unchanged.

## Implementation

- `CacheProducerIdentity` validates nonblank GAV. Release build metadata may be absent or a canonical lowercase SHA-256 and is ignored for compatibility; release compatibility is exact GAV. SNAPSHOT requires a canonical lowercase SHA-256 and compatibility additionally requires exact digest equality.
- `VulnerabilityCacheEnvelopeWriter` and `VulnerabilityCacheEnvelopeReader` encode/decode the outer schema-v1 envelope with exact fields, strict duplicate/trailing JSON checks, producer validation, and compatibility validation.
- `AdvisoryEvidenceWriter.encodeTree` and `AdvisoryEvidenceReader.readTree` expose shared validation and deterministic encoding as native JSON trees, avoiding a full nested serialization/reparse during envelope composition.
- Decoded data remains review-only typed advisory evidence; this checkpoint does not create or modify live configured POM proof inputs.

## Independent review

Approved with no remaining findings. The reviewer confirmed release compatibility ignores optional valid build metadata while retaining exact GAV matching, SNAPSHOT identity requires exact canonical digest matching, and the envelope reuses strict nested advisory validation without repeated full-payload serialization.

## Verification

- `make fmt`: passed.
- `make lint-java`: passed with Checkstyle, PMD, and SpotBugs clean.
- Focused core selectors `CacheProducerIdentityTest`, `VulnerabilityCacheEnvelopeCodecTest`, and `VulnerabilityCacheEnvelopeRejectionTest`: 6/6 passed.
- Each command used JDK 21 and an explicit 600-second hard timeout. Examples and full `make check` were not run for this bounded checkpoint.

## Remaining AC12 integration

Resolve the installed plugin's GAV/build identity; wire the envelope into the local vulnerability cache; add producer identity compatibility gates to the trim-output cache; and test online rebuild/offline cache miss behavior for missing or mismatched identities. These remain deferred to the production integration slice.
