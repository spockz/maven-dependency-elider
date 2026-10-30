<!-- WHY: Defines the audited GraalVM Native Image input boundary, root inference rules, and permissive handling of unrelated arguments. -->
# ADR-0009: Bounded GraalVM Native Image Root Inference

* **Status**: Accepted
* **Date**: 2026-10-30

<!-- semedit-adr-metadata:v1 keys=summary,description,role,scope,area,languages; do not change key names or order. -->
| Key | Value |
| :--- | :--- |
| summary | Model the audited GraalVM Native Image 21.0.12+7.1 class, package, configuration, and reachability inputs with explicit bounded semantics. |
| description | Parse enumerated reference inputs or fail clearly; accept valid unknown options without inferred roots and make no completeness claim for them. |
| role | architecture |
| scope | dynamic-reachability |
| area | plugin-core |
| languages | java |

## Context

Native Image metadata can preserve classes that bytecode analysis cannot discover, including reflection, JNI, proxy, serialization, feature, and initialization targets. Rejecting every unfamiliar compiler argument makes ordinary dependencies unusable. Treating every unfamiliar argument as harmless and claiming complete roots would also be unsafe: future options may declare classes.

The available audit is GraalVM Native Image 21.0.12+7.1's `native-image --expert-options-all`. This decision bounds completeness to the explicit modeled inventory below and the documented descriptor schemas. It makes no universal claim for arbitrary future or unknown options.

## Decision

### Argument handling

* Parse audited reference-bearing options. A recognized option with a malformed or unreadable reference fails with a diagnostic. Empty values fail unless the option's documented initialization semantics make the empty target whole-scope.
* Accept syntactically valid options outside the audited inventory without inferring roots. Unknown options that carry class references are outside the guarantee.
* Do not expose `allowedNativeImageArgs` or `failOnUnsupportedNativeImageArgs`; these unreleased controls are removed rather than retained as inert switches.
* Reject `@argfile`, classpath/module-path, and other recognized indirections that could hide roots unless the input is explicitly modeled and completely read. Do not silently treat a recognized unreadable reference as an unknown option.
* Bare and explicitly empty `--initialize-at-build-time` and `--initialize-at-run-time` forms are whole-inventory retention targets. Native Image may reject the build-time empty form unless its deprecated override is enabled, and documents the runtime empty form as unsupported. Retention inference does not promise Native Image build acceptance.

### Audited direct and policy options

The option inventory below is the audited boundary. Option names are exact; no `-H:` or `--` prefix rule is implied.

| Exact option(s) | Value shape | Root action |
| :--- | :--- | :--- |
| `--features`, `-H:Features` | Comma-separated binary class names | Add each feature class as a class root. |
| `-H:Class`, `--main-class` | One binary class name | Add the entry class as a class root. |
| `--initialize-at-build-time`, `--initialize-at-run-time` | Bare or `=<class-or-package-list>` | Bare and explicitly empty forms are whole-inventory retention targets; non-empty lists add the named class/package roots. The build-time empty form may be rejected by Native Image unless its deprecated override is enabled; the runtime empty form is documented unsupported. Retention inference does not promise Native Image build acceptance. |
| `-H:ClassInitialization` | Comma-separated `class-or-package:strategy` entries | Accept exactly `build_time`, `rerun`, or `run_time`. Named targets add class/package roots; an empty target with a valid strategy pins the complete dependency inventory. A missing strategy, including bare `-H:ClassInitialization` or `-H:ClassInitialization=`, is invalid. |
| `--trace-class-initialization`, `-H:TraceClassInitialization`; `--trace-object-instantiation`, `-H:TraceObjectInstantiation` | Comma-separated binary class names | Add each named class as a root. |
| `-H:AdditionalSecurityProviders`, `-H:AdditionalSecurityServiceTypes` | Comma-separated binary class names | Add each named type as a root. |
| `-H:IncludeResourceBundles` | Comma-separated bundle names | Retain resource bundles; add a type root when a bundle name is a valid binary class name. |
| `-H:LinkAtBuildTime`, `--link-at-build-time` | Comma-separated type names; bare means all classes in the applicable scope | Add named types; bare form is a broad policy and pins the applicable dependency scope. |
| `-H:LinkAtBuildTimePaths`, `--link-at-build-time-paths` | Host `File.pathSeparator`-separated classpath/module-path entries | Resolve entries and add their indexed classes as roots; unresolved/unsupported indirection is an error. Snapshot each normalized logical path alias and verify that it still resolves to the same canonical indexed archive before publication. |
| `-H:ReflectionConfigurationFiles`, `-H:JNIConfigurationFiles`, `-H:DynamicProxyConfigurationFiles`, `-H:SerializationConfigurationFiles`, `-H:PredefinedClassesConfigurationFiles`, `-H:ResourceConfigurationFiles`, `-H:ForeignConfigurationFiles`, `-H:ObjectInliningConfigurationFiles` | Comma-separated filesystem paths | Resolve relative to the explicitly supplied Maven invocation base; parse with the option's schema/semantics or fail. |
| `-H:ReflectionConfigurationResources`, `-H:JNIConfigurationResources`, `-H:DynamicProxyConfigurationResources`, `-H:SerializationConfigurationResources`, `-H:PredefinedClassesConfigurationResources`, `-H:ResourceConfigurationResources`, `-H:ForeignResources`, `-H:ObjectInliningConfigurationResources`, `-H:ReachabilityMetadataResources` | Comma-separated classpath resource names | Process all matching entries sorted by normalized artifact coordinate then normalized archive path, and entries by name; deduplicate resulting roots. Parse with the option's schema/semantics or fail. |
| `-H:ConfigurationFileDirectories` | Comma-separated filesystem directories | Resolve from the invocation base; traverse directly contained metadata deterministically with cycle/dedup controls. |
| `-H:ConfigurationResourceRoots` | Comma-separated classpath directory roots | Traverse matching resources across all candidate archives deterministically with cycle/dedup controls. |

`-H:ForeignConfigurationFiles` and `-H:ForeignResources` parse the standalone `downcalls` ABI format and add no Java class roots. Only unified schema 1.2.0 `foreign.directUpcalls[].class` fields add class roots. Object-inlining configuration is parsed as its own input format and contributes each declared class/type reference. Missing, escaping, or malformed paths fail explicitly.

These audited options affect reachability but do not declare positive class roots; apply only the listed behavior:

| Exact option(s) | Effect and parser action |
| :--- | :--- |
| `-H:+EnableAllSecurityServices`, `-H:-EnableAllSecurityServices`, `--enable-all-security-services` | Broad security-service inclusion policy. Enabled forms pin the complete dependency class scope because the included service classes are not enumerated by this option. |
| `-H:+EnableSecurityServicesFeature`, `-H:-EnableSecurityServicesFeature` | Automatic JCA service registration (enabled by default). Graal discovers service implementations when JCA `getInstance` factory methods are reachable, using the provider list captured at image-build time. The toggle itself adds no named roots; the elider models explicitly named providers and custom service types only through `-H:AdditionalSecurityProviders` and `-H:AdditionalSecurityServiceTypes`, and makes no claim to infer every provider candidate selected by Graal. |
| `-H:EnableURLProtocols`, `-H:DisableURLProtocols`, `--enable-url-protocols` | Comma-separated nonempty tokens; validate without URL grammar or case normalization. Enabled forms pin the complete dependency class scope; disabled forms add no roots and never subtract other roots. |
| `-H:+UseServiceLoaderFeature`, `-H:-UseServiceLoaderFeature` | Exact toggle forms. When enabled, add service interfaces and non-excluded providers from all parsed `META-INF/services` descriptors invocation-wide, even when conservative ServiceLoader roots are disabled. |
| `-H:ServiceLoaderFeatureExcludeServices=`, `-H:ServiceLoaderFeatureExcludeServiceProviders=` | Comma-separated binary class names; validate and aggregate across all properties. Exclude services/providers only from this feature-derived root set; direct roots and ordinary conservative ServiceLoader roots remain. Exclusion values add no roots. |
| `-H:SerializationDenyConfigurationFiles`, `-H:SerializationDenyConfigurationResources` | Deny-listed serialization types are not positive roots; still resolve and validate these recognized references. |

The following additional audited options do not name a class root. They are handled according to their narrower no-root or broad-policy semantics:

| Exact option(s) | Value/effect | Parser action |
| :--- | :--- | :--- |
| `-H:+AddAllCharsets`, `-H:-AddAllCharsets`, `-H:+ReportUnsupportedElementsAtRuntime`, `-H:-ReportUnsupportedElementsAtRuntime`, `-H:+AllowIncompleteClasspath`, `-H:-AllowIncompleteClasspath`, `-H:+PrintAnalysisCallTree`, `-H:-PrintAnalysisCallTree`, `--report-unsupported-elements-at-runtime`, `--report-exception-stack-traces`, `--allow-incomplete-classpath`, `--verbose`, `--diagnostics-mode` | Diagnostic or JDK image configuration | Accept without dependency class roots. |
| `--enable-http`, `--enable-https` | JDK HTTP/HTTPS support | Accept without dependency class roots. |
| `-H:+AddAllFileSystemProviders`, `-H:-AddAllFileSystemProviders`, `-H:+IncludeAllLocales`, `-H:-IncludeAllLocales` | Enables providers/locales available from the image classpath | Enabled forms pin the applicable dependency scope; disabled forms add no roots. |
| `--no-fallback`, `--force-fallback`, `--auto-fallback`, `--install-exit-handlers`, `--static`, `--shared`, `--libc=<value>`, `-O0`, `-O1`, `-O2`, `-O3`, `-Os`, `-Ob`, `-march=<value>`, `--pgo`, `--pgo-instrument`, `--gc=<value>`, `-H:+SpawnIsolates`, `-H:-SpawnIsolates`, `-R:MaxHeapSize=<value>`, `-H:Name=<value>`, `--enable-sbom`, `--enable-preview`, `--enable-monitoring=<value>` | Linker, fallback, optimization, runtime, monitoring, or output settings | Accept without dependency class roots. |
| `-H:IncludeResources`, `-H:ExcludeResources` | Optional module selector followed by one whole-string regular expression | Compile the complete regex value without comma splitting; match raw archive entry names and each name plus `/`. Include matches retain all matching providers and add logical roots for matched class entries, including MRJAR entries. Exclusions take precedence for pattern-derived providers and class roots, but do not remove roots from other options. `ALL-UNNAMED` selects the indexed classpath; named selectors match no indexed classpath entries. |

Other syntactically valid options are accepted without inferred roots. Unknown future options that name classes remain outside the guarantee. The list above is explicit; it does not imply a general `-H:` or `--` no-root rule.

The earlier work-package handover lists `-H:MaxHeapSize=<value>` as a non-class example, but the pinned expert list exposes `-R:MaxHeapSize`; the `-H:` spelling is therefore accepted as an unknown and is not an audited no-root option. Other handover examples absent from the pinned inventory also follow the valid-unknown rule. No blanket `-H:` or `--` no-root rule applies.

### Descriptor formats

Supported standalone JSON schemas are version 1.0.0 for `reflect-config.json`, `jni-config.json`, `proxy-config.json`, `serialization-config.json`, `predefined-classes-config.json`, and `resource-config.json`. Unified `reachability-metadata.json` uses schema version 1.2.0. Standalone foreign files use the option-specific `downcalls` ABI descriptor shape (optional array entries with a `descriptor` string and optional typed `options`) and contain no Java class references. Unified schema 1.2.0 `foreign` is separate and supports downcalls, upcalls, and direct upcalls. Object-inlining files use the separately audited Native Image map format with six optional maps: `value_fields`, `value_graphs`, `value_fields_mutable`, `value_graphs_mutable`, `value_field_types`, and `value_graph_types`. Their keys are class/type names; selector strings are validated but not treated as roots. Serialization-deny files are validated and add no positive roots.

Standalone reflection/JNI entries require `name`; `type`, `access`, `jniAccessible`, and `serializable` aliases are rejected. The pinned JDK21 parser's boolean flags are `allDeclaredConstructors`, `allPublicConstructors`, `allDeclaredMethods`, `allPublicMethods`, `allDeclaredFields`, `allPublicFields`, `allDeclaredClasses`, `allPublicClasses`, `allRecordComponents`, `allPermittedSubclasses`, `allNestMembers`, `allSigners`, `queryAllDeclaredConstructors`, `queryAllPublicConstructors`, `queryAllDeclaredMethods`, `queryAllPublicMethods`, and `unsafeAllocated`. Method entries retain `name` and optional `parameterTypes`; field entries retain `name`, `allowWrite`, and `allowUnsafeAccess`. Conditions are class-name strings. Proxy interfaces and conditions, serialization types, proxy interfaces, `lambdaCapturingTypes`, `customTargetConstructorClass`, and predefined bytecode references are modeled as roots.

The pinned `resource-config.json` parser accepts `resources`, `bundles`, and `globs` independently. `resources` may be a legacy array or an object with required `includes` and optional `excludes`; pattern entries accept only `pattern` and optional `condition`. Bundle entries accept `name` with optional `condition`, `locales`, and `classNames`; locale strings are validated but add no class roots. Bundle names are resource-family names and may include locale suffixes that are not valid Java class names. `globs` entries accept `glob` with optional `condition` and `module`. These accepted legacy arrays and top-level globs are pinned JDK21 parser extensions alongside standalone resource-config schema 1.0.0. Glob matching follows the pinned converter: `*` stays within a path segment, `**` spans segments, `**/` also matches zero directories, and other characters are literal. Regex values use a first-colon module selector; glob descriptors use their explicit `module` field. Resource patterns, globs, and bundle names are collected while candidate descriptors are parsed and resolved only after the complete invocation archive index is available. Matching providers are retained; matching `.class` resources add their existing logical class names, including MRJAR variants. Bundle requests select matching locale `.properties`/`.class` families across archives and root only class variants present in the logical inventory; a properties-only bundle does not synthesize a class root. `classNames` and condition classes remain direct class roots. A standalone `resources.excludes` selector suppresses both regex and glob selections from that descriptor's resource sections; it does not suppress bundles, condition classes, `classNames`, or selections from another descriptor. Unified resource module selectors and regex module selectors match indexed classpath resources only when absent or `ALL-UNNAMED`; named modules match none. Conditional resource selections are resolved conservatively without evaluating their condition, while the condition class remains a root.

Predefined `nameInfo` is optional; resolve each hash to `agent-extracted-predefined-classes/<hash>.classdata` relative to the configuration directory, derive its class name and references from those bytes, and preserve the classdata resource. Reject unresolved hashes. Unified schema 1.2.0 supports exactly `reflection`, `resources`, and `foreign` top-level sections. Reflection types may be class names, proxy descriptors, or lambda descriptors; methods include parameter types. Resources support conditional `glob` and `bundle` entries. Only unified direct-upcall `class` fields add a Java class root; standalone foreign ABI function strings do not. The schema does not define top-level `jni`, `serialization`, or `proxy` sections; those keys are rejected. Invalid JSON, duplicate keys, trailing values, unsupported fields, and invalid type descriptors fail closed. Serialization-deny proxy/type names are validated without requiring classes to occur in the scanned inventory and never become positive roots.

### Package boundary

Package initialization roots match classes in the named package and descendant packages, but not similarly prefixed sibling packages (for example `com.acme` matches `com.acme.Tool` and `com.acme.internal.Helper`, not `com.acmeextra.Tool`). Expansion uses all dependency archives, including multi-release class inventory, so packages can span JARs.

## Consequences

Valid compiler flags no longer force pass-through or stop analysis. A recognized unreadable reference cannot silently disappear from the root model. Root inference remains explicit and reviewable, with a clear boundary against unmodeled future options. The parser inventory, descriptor reader, tests, and user documentation must be updated together when this audited contract changes.
