<!-- WHY: Records the evidence and bounded option/descriptor taxonomy for GraalVM Native Image dynamic-root ingestion. -->
# RQ-0016: GraalVM Native Image Metadata Ingestion and Argument Taxonomy

## Status

In progress

## Date

2026-10-30

## Category

Dynamic Reachability & Native-Image Integration

## 1. Question and Evidence Boundary

How can dependency trimming retain classes named by GraalVM Native Image metadata without rejecting ordinary compiler options or assuming unknown options are harmless?

The implementation audit is pinned to GraalVM Native Image 21.0.12+7.1 `native-image --expert-options-all`. The modeled inventory includes direct class and package options, security type lists, initialization and reachability toggles, resource/configuration pointers, and selected descriptor schemas. The inventory must list concrete option names and value semantics. It does not establish universal completeness for future or unknown flags.

## 2. Handling Contract

1. Recognized class, package, and configuration references are parsed as roots or fail clearly if malformed or unreadable.
2. Syntactically valid options outside the audited inventory are accepted with no inferred roots. A future unknown option may declare classes; this remains outside the guarantee.
3. Root names are validated. Package roots expand at exact package boundaries over the complete dependency archive index, including multi-release classes.
4. Bare initialization options mean whole-image initialization policy and add no roots; explicitly empty values are invalid.
5. Configuration `*Resources` point to classpath resources; `*Files` point to external files. `ConfigurationResourceRoots` traverse classpath directories across candidate archives. `ConfigurationFileDirectories` resolve from the explicit Maven invocation base. Duplicate classpath resources resolve deterministically. Directory and resource-root traversal is deterministic, deduplicated, and cycle controlled.
6. `@argfile`, classpath/module-path, and other indirect root sources must not bypass modeling. Reject unsupported or unreadable forms explicitly.

The unreleased `allowedNativeImageArgs` and `failOnUnsupportedNativeImageArgs` controls have no role in this contract and are removed end-to-end.

## 3. Descriptor Scope

The modeled schemas are reflection, JNI, proxy, serialization, predefined classes, resource configuration, and supported unified reachability metadata sections. Required type extraction includes principal types, conditions, method parameter types, proxy interfaces, serialization types and lambda capturing types, custom target constructors, and optional predefined `nameInfo`. A predefined hash-only entry must resolve its associated bytecode/reference data or fail explicitly. Malformed JSON, duplicate keys, trailing documents, malformed paths, and unsupported structures fail closed.

See [ADR-0009](../adr/0009-permissive-graalvm-native-image-metadata-ingestion.md) for the current option inventory summary and compatibility boundary. The parser and its regression tests are the executable inventory; this research record does not imply support beyond those cases.

## 4. Verification Questions

* Does each audited reference option have tests for valid roots, missing/empty values, malformed names, and archive or filesystem path failures?
* Do directory/resource-root tests prove deterministic traversal and cycle/dedup behavior across candidate archives?
* Do descriptor tests cover type-valued fields and optional fields without weakening strict validation?
* Do mixed-option integration tests prove that modeled dynamic classes survive while an unrelated class is physically trimmed?
* Does package initialization retain matching classes across dependency archives while excluding similarly prefixed packages?
* Are cache and pass-through paths free of the removed allowlist and strictness policy state?

These questions are acceptance gates for WP-NATIVE-02. Passing them supports the bounded audited inventory only.
