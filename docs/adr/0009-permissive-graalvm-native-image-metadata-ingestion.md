<!-- WHY: Defines the audited GraalVM Native Image input boundary, root inference rules, and permissive handling of unrelated arguments. -->
# ADR-0009: Bounded GraalVM Native Image Root Inference

* **Status**: Accepted
* **Date**: 2026-10-30

<!-- semedit-adr-metadata:v1 keys=summary,description,role,scope,area,languages; do not change key names or order. -->
| Key | Value |
| :--- | :--- |
| summary | Infer dynamic roots from an explicit GraalVM Native Image 21.0.12+7.1 input inventory while accepting unrelated and unknown valid arguments. |
| description | Model audited class/package options, configuration paths, and descriptor schemas; fail on malformed recognized references and accept valid unmodeled options without roots. |
| role | architecture |
| scope | dynamic-reachability |
| area | plugin-core |
| languages | java |

## Context

Native Image metadata can preserve classes that bytecode analysis cannot discover, including reflection, JNI, proxy, serialization, feature, and initialization targets. Rejecting every unfamiliar compiler argument makes ordinary dependencies unusable. Treating every unfamiliar argument as harmless and claiming complete roots would also be unsafe: future options may declare classes.

The available audit is GraalVM Native Image 21.0.12+7.1's `native-image --expert-options-all`. This decision bounds completeness to the explicit modeled inventory below and the documented descriptor schemas. It makes no universal claim for arbitrary future or unknown options.

## Decision

### Argument handling

* Parse audited reference-bearing options. A recognized option with an empty, malformed, missing, or unreadable reference fails with a diagnostic.
* Accept syntactically valid options outside the audited inventory without inferring roots. Unknown options that carry class references are outside the guarantee.
* Do not expose `allowedNativeImageArgs` or `failOnUnsupportedNativeImageArgs`; these unreleased controls are removed rather than retained as inert switches.
* Reject `@argfile`, classpath/module-path, and other recognized indirections that could hide roots unless the input is explicitly modeled and completely read. Do not silently treat a recognized unreadable reference as an unknown option.
* Bare initialization options specify whole-image policy and add no package roots. An explicitly empty `--initialize-at-build-time=` or `--initialize-at-run-time=` value is malformed.

### Audited direct and policy options

The implementation inventory is pinned to GraalVM Native Image 21.0.12+7.1. It includes:

* Class or package references: `--features`, `-H:Features`, `-H:Class`, `--main-class`, class-initialization options (`--initialize-at-build-time`, `--initialize-at-run-time`, `-H:ClassInitialization`), class tracing options (`--trace-class-initialization`, `-H:TraceClassInitialization`, `--trace-object-instantiation`, `-H:TraceObjectInstantiation`), and security provider/service type options (`-H:AdditionalSecurityProviders`, `-H:AdditionalSecurityServiceTypes`). Package targets are represented explicitly and expanded over the complete dependency archive class index at package boundaries.
* Resource bundle options retain bundle class names and declared conditions where they represent types. Resource regexes and resource payloads are not class roots.
* Configuration pointers: reflection, JNI, dynamic proxy, serialization, predefined classes, reachability metadata, and resource configuration `*Resources` and `*Files` options; configuration-file directories and resource roots; and the audited foreign and object-inlining configuration inputs. `Resources` resolve as classpath resources; `Files` resolve as filesystem files. `ConfigurationResourceRoots` are classpath directories and may span candidate archives. `ConfigurationFileDirectories` resolve from the Maven invocation base directory, which is passed explicitly. Duplicate classpath resource paths have deterministic resolution. Directory/resource-root traversal is deterministic, deduplicated, and cycle controlled. Missing, escaping, or malformed paths fail explicitly.
* Inclusion or analysis policy toggles that change reachability without naming individual classes are explicitly inventoried and handled according to their semantics; they are not treated as unknown class-name lists.

The complete audited option names, value shapes, and parser actions are maintained with the implementation and its regression tests. This summary is not a wildcard rule for all `-H:` or `--` options.

### Descriptor formats

Supported metadata includes `reflect-config.json`, `jni-config.json`, `proxy-config.json`, `serialization-config.json`, `predefined-classes-config.json`, `resource-config.json`, and the modeled sections/type forms of `reachability-metadata.json`.

Class roots include reflection/JNI principal types, conditions, and method parameter types; proxy interfaces and conditions; serialization types, lambda capturing types, proxy interfaces, and custom target constructor classes; and predefined class names when `nameInfo` is present. Predefined entries that provide only hashes require associated bytecode/reference data to be resolvable; otherwise the recognized input is rejected, not treated as root-free. Unified metadata supports its declared reflection, JNI, serialization, proxy, and type descriptor sections. Optional fields remain optional. Invalid JSON, duplicate keys, trailing values, unsupported modeled structure, and invalid type descriptors fail closed.

### Package boundary

Package initialization roots match classes in the named package and descendant packages, but not similarly prefixed sibling packages (for example `com.acme` matches `com.acme.Tool` and `com.acme.internal.Helper`, not `com.acmeextra.Tool`). Expansion uses all dependency archives, including multi-release class inventory, so packages can span JARs.

## Consequences

Valid compiler flags no longer force pass-through or stop analysis. A recognized unreadable reference cannot silently disappear from the root model. Root inference remains explicit and reviewable, with a clear boundary against unmodeled future options. The parser inventory, descriptor reader, tests, and user documentation must be updated together when this audited contract changes.
