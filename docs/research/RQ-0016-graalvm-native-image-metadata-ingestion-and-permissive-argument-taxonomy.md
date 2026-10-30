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

The implementation audit is pinned to GraalVM Native Image 21.0.12+7.1 `native-image --expert-options-all` and `native-image --help`. Its exact root-bearing inputs include `--features`/`-H:Features`, `-H:Class`/`--main-class`, `--initialize-at-build-time`, `--initialize-at-run-time`, `-H:ClassInitialization`, initialization/object tracing options, `-H:AdditionalSecurityProviders`, `-H:AdditionalSecurityServiceTypes`, `-H:IncludeResourceBundles`, `-H:LinkAtBuildTime`/`--link-at-build-time`, and `-H:LinkAtBuildTimePaths`/`--link-at-build-time-paths`. Configuration inputs include the reflection, JNI, dynamic-proxy, serialization, serialization-deny, predefined-class, resource, foreign, and object-inlining `ConfigurationFiles`/`ConfigurationResources` pairs, `-H:ReachabilityMetadataResources`, `-H:ConfigurationFileDirectories`, and `-H:ConfigurationResourceRoots`. The option table in [ADR-0009](../adr/0009-permissive-graalvm-native-image-metadata-ingestion.md) specifies each value shape and parser action. These are exact names, not prefix rules.

## 2. Handling Contract

1. Recognized class, package, and configuration references are parsed as roots or fail clearly if malformed or unreadable.
2. Syntactically valid options outside the audited inventory are accepted with no inferred roots. A future unknown option may declare classes; this remains outside the guarantee.
3. Root names are validated. Package roots expand at exact package boundaries over the complete dependency archive index, including multi-release classes.
4. Bare and explicitly empty `--initialize-at-build-time` and `--initialize-at-run-time` forms are whole-inventory retention targets; class/package lists retain their matching types. Native Image may reject the empty build-time form unless its deprecated override is enabled, and documents the empty runtime form as unsupported; elider retention inference does not promise build acceptance. `-H:ClassInitialization` takes comma-separated class-or-package targets with exactly `build_time`, `rerun`, or `run_time` strategies; an empty target plus a valid strategy pins the full dependency inventory, while a missing strategy (including the bare option) is invalid. `LinkAtBuildTime` with no value and enabled `EnableAllSecurityServices`/`--enable-all-security-services` are broad inclusion policies and pin the applicable dependency scope. `EnableSecurityServicesFeature` (default enabled) uses reachable JCA `getInstance` factory methods and the provider list captured at image-build time; the toggle alone names no classes. This inventory models explicit provider/service roots only through `AdditionalSecurityProviders` and `AdditionalSecurityServiceTypes`, and does not claim to reconstruct every Graal-selected provider candidate. `UseServiceLoaderFeature` relies on parsed service descriptors; service exclusions and serialization-deny entries are validated but do not become positive roots. `--enable-url-protocols` can include URL handlers and is also a broad dependency policy.
5. Configuration `*Resources` point to classpath resources; `*Files` point to external files. `ConfigurationResourceRoots` traverse classpath directories across candidate archives. `ConfigurationFileDirectories` resolve from the explicit Maven invocation base. Process all matching classpath resources sorted by normalized artifact coordinate then normalized archive path, and entries by name; deduplicate resulting roots. Directory and resource-root traversal is deterministic, deduplicated, and cycle controlled.
6. `@argfile`, classpath/module-path, and other indirect root sources must not bypass modeling. Reject unsupported or unreadable forms explicitly.

The pinned option inventory contains `-R:MaxHeapSize` as a runtime setting, not `-H:MaxHeapSize`; the latter spelling from the earlier handover remains a valid unknown argument and receives no inferred semantics.

The unreleased `allowedNativeImageArgs` and `failOnUnsupportedNativeImageArgs` controls have no role in this contract and are removed end-to-end.

## 3. Descriptor Scope

Supported standalone schemas are version 1.0.0 for reflection, JNI, proxy, serialization, predefined classes, and resource configuration. Unified `reachability-metadata.json` uses schema 1.2.0 and supports exactly `reflection`, `resources`, and `foreign` root sections. Standalone reflection requires `name`; `type`, `access`, `jniAccessible`, and `serializable` are rejected. Its pinned boolean flags include all declared/public constructors, methods, fields, classes, record components, permitted subclasses, nest members, signers, `queryAll*` constructors/methods, and `unsafeAllocated`. Method parameter types are roots; field entries validate `name`, `allowWrite`, and `allowUnsafeAccess`. Standalone conditions accept a class-name string under exactly one of `typeReached` or `typeReachable`.

The pinned `resource-config.json` parser accepts `resources`, `bundles`, and `globs` independently. Resources are a legacy array or an object with required `includes` and optional `excludes`; pattern entries accept `pattern` and optional `condition`. Bundles retain `name`, optional `classNames`, and condition types; optional `locales` strings are validated without adding class roots. Top-level globs accept `glob` with optional `condition` and `module`. These array and glob forms are pinned JDK21 parser extensions in addition to resource schema 1.0.0. Unified resources include conditional `glob` and `bundle` entries.

Unified reflection types include class-name, proxy, and lambda descriptors. Unified foreign supports downcalls, upcalls, and direct upcalls; only direct-upcall `class` fields are class roots. Standalone foreign files use the separate `downcalls` ABI descriptor shape with optional `descriptor` and `options` fields and contain no Java class references. Unified top-level `jni`, `serialization`, and `proxy` keys are rejected. Standalone extraction includes principal types, conditions, proxy interfaces, serialization types, proxy interfaces, `lambdaCapturingTypes`, and `customTargetConstructorClass`. Predefined `nameInfo` is optional; resolve hashes to `agent-extracted-predefined-classes/<hash>.classdata` relative to the config directory and derive class names/references from bytecode, rejecting unresolved hashes and preserving the classdata resource. Object-inlining files use the six audited `value_*` maps keyed by class/type names; selector strings are validated without becoming roots. Serialization-deny files and their proxy/type names are validated without requiring classes to occur in the inventory and add no positive roots. See [ADR-0009](../adr/0009-permissive-graalvm-native-image-metadata-ingestion.md) for the complete option and schema contract.

The parser and regression tests must match this explicit inventory and schema boundary. Neither record implies support for unknown future options or schemas.

## 4. Verification Questions

* Does each audited reference option have tests for valid roots, missing/empty values, malformed names, and archive or filesystem path failures?
* Do directory/resource-root tests prove deterministic traversal and cycle/dedup behavior across candidate archives?
* Do descriptor tests cover type-valued fields and optional fields without weakening strict validation?
* Do mixed-option integration tests prove that modeled dynamic classes survive while an unrelated class is physically trimmed?
* Does package initialization retain matching classes across dependency archives while excluding similarly prefixed packages?
* Are cache and pass-through paths free of the removed allowlist and strictness policy state?

These questions are acceptance gates for WP-NATIVE-02. Passing them supports the bounded audited inventory only.
