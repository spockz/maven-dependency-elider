<!-- WHY: Defines the investigation needed to turn Spring bean lifecycle and dependency evidence into cautious, testable auto-configuration recommendations, kept separate from the core artifact elision decision. -->
# RQ-0005: Spring Bean Request Evidence and Auto-Configuration Recommendations

* **Status**: Open
* **Category**: Framework Evidence & Recommendations
* **Date**: 2026-10-25
* **Last Updated**: 2026-10-25

Abbreviations: Application Programming Interface (API), Application Context (context), Spring Boot (Boot), Maven Dependency Elider (Elider).

## 1. Context

Runtime class loading and execution evidence alone cannot distinguish framework setup from application behavior. A bean may be instantiated during context startup, or its classes may be loaded while Boot evaluates conditional auto-configuration, even when application code never requests that capability. Conversely, a bean or method absent from one workload may be required by a later request, scheduled task, retry, error path, profile, or deployment setting.

Spring Boot provides condition evaluation diagnostics, and Spring bean factories expose declared bean dependency relationships. These signals can help identify auto-configured capabilities that appear unnecessary in a measured application context. They are evidence for investigation, not proof that an auto-configuration or dependency can be removed.

One ambiguity is whether a starter's beans support application features or are only loaded or touched during auto-configuration, health checks, or metrics collection. Record the triggering context where possible. Health and metrics observations must remain distinguishable from application-feature requests; they may still represent required operational behavior and cannot simply be discarded.

This research question defines an optional Spring-aware evidence collector and recommendation report. It does not change the core whole-artifact elision rule or automatically add recommendations to the Elider's global exclusion list.

## 2. Research Questions

* **RQ-0005.1**: Which Spring lifecycle points can reliably record bean definitions, bean creation, bean requests, and dependency edges, including lazy beans and prototype/scoped beans?
* **RQ-0005.2**: How can each observed bean be attributed to its defining configuration and, where possible, to the exact Maven artifact that supplied it?
* **RQ-0005.3**: How complete are Spring's declared dependency edges for constructor/setter injection, `@DependsOn`, programmatic lookups, providers, events, and framework-managed callbacks?
* **RQ-0005.4**: Can a transitive chain of unrequested beans identify a candidate auto-configuration without incorrectly labeling lifecycle infrastructure or capabilities exercised only outside the recorded workload?
* **RQ-0005.5**: What repeatable verification is required before recommending exclusion of an auto-configuration or removal of its starter, and how should this be distinguished from the Elider's global retention exclusions?
* **RQ-0005.6**: How can bean use triggered only by health checks or metrics scrapes be identified and reported separately from application-feature requests without assuming it is operationally unnecessary?

## 3. Proposed Evidence Model

The collector should record distinct evidence states rather than collapse them into “used” and “unused”:

1. **Condition outcome**: auto-configuration or bean condition matched, did not match, or has no available outcome, including the reported reason where available.
2. **Definition**: bean definition was registered, with bean name/type, factory method or definition origin, scope, lazy flag, and originating configuration when resolvable.
3. **Creation/request**: bean instance was created or requested during the recording interval. These are separate facts; eager singleton creation does not establish application-level demand. Record whether the trigger was an application endpoint/background task, a health check, metrics collection, or another known context.
4. **Dependency edge**: bean A declared or was observed requesting bean B. Preserve the edge source and confidence; do not imply a complete graph where only declared edges are available.
5. **Runtime code evidence**: available class/method telemetry for the owning artifact. This supplements bean evidence but does not replace it.
6. **Artifact attribution**: exact artifact origin only when available from class/resource provenance. Do not infer the owner solely from a class name when duplicates exist.

The report should say **“not observed in this context/workload”**, never assert **“unused”** from absence alone. Missing telemetry, incomplete dependency edges, and unattributed origins must remain explicit.

## 4. Recommendation Workflow

For each candidate auto-configuration:

1. Show its condition outcome and the beans it defined, including provenance and observed request/creation status.
2. Show dependency chains that lead only to beans not requested during the recording, while marking incomplete or indirect edges.
3. Recommend a targeted exclusion for evaluation, naming the exact auto-configuration class and the evidence behind the recommendation.
4. Re-run representative application tests and workloads with that exclusion. Include startup, relevant endpoints, scheduled/background behavior, and important failure/retry paths for the application.
5. Only after the excluded configuration passes those checks should the user consider removing the associated starter. Confirm the resolved dependency graph because a starter may contain multiple configurations or share dependencies with other features.
6. Keep exclusion meanings explicit. `spring.autoconfigure.exclude` disables named auto-configurations; a Maven dependency exclusion removes a transitive resolution path. The Elider's `excludedArtifacts` instead excludes coordinates from elision and therefore retains them across the current project's dependency graph. It is not a forced-removal list or automatically a policy for multiple projects. A future force-remove policy would need a separate contract.

Disabling an auto-configuration and removing a starter are separate experiments. Classpath removal can change other conditional configurations, service discovery, and fallback behavior. Re-run the conditions report and application workload after dependency removal; success with only the auto-configuration excluded does not validate the changed classpath.

Recommendations must not mutate the Maven project, remove dependencies, or populate global exclusions automatically. The final choice remains explicit and reviewable.

## 5. Experimental Plan

Use the Spring Boot reference application from RQ-0002 and add fixtures for:

* an eagerly created bean that is not requested by application code;
* a lazy bean requested only by a selected endpoint;
* a bean used only on an error/retry path;
* multiple beans where an apparently unrequested auto-configured bean is a dependency of another bean;
* a conditionally registered bean whose condition matches but whose capability is not exercised;
* a bean loaded or requested only by health checks or metrics, alongside a separate application-feature request fixture;
* a bean contributed by application code overriding an auto-configured bean;
* duplicate class names across artifacts or an origin that cannot be attributed reliably.

For each fixture, compare condition evaluation, bean definitions, creation/request observations, dependency edges, class/method telemetry, and artifact origins. Then disable the candidate auto-configuration and verify expected success or failure using integration tests. Record any framework lifecycle behavior that makes absence ambiguous.

## 6. Acceptance Criteria

* [ ] Identify the least invasive Spring extension points that can capture bean definitions, requests/creation, origins, and dependency relationships across the supported Boot versions.
* [ ] Specify the evidence format, confidence/coverage markers, and attribution behavior, including unresolved and duplicate origins.
* [ ] Demonstrate correct distinctions between matched condition, registered bean, created bean, requested bean, and observed application execution in the fixtures.
* [ ] Distinguish health/metrics-only bean activity from application-feature requests, while retaining it as separately reviewable operational evidence.
* [ ] Produce recommendations that identify candidate auto-configurations and explain their supporting and missing evidence.
* [ ] Verify that recommendations do not themselves mutate dependency resolution or the global exclusion list.
* [ ] Demonstrate an explicit exclude-and-test workflow that catches a feature exercised only on a non-default path.
* [ ] Distinguish Spring auto-configuration exclusions, Maven dependency exclusions, and Elider retention exclusions in recommendations and examples.

## 7. Related Work

* Spring Boot's [auto-configuration diagnostics and exclusion mechanisms](https://docs.spring.io/spring-boot/reference/using/auto-configuration.html) report condition outcomes and allow explicit exclusions.
* Spring Framework's [ConfigurableBeanFactory API](https://docs.spring.io/spring-framework/docs/current/javadoc-api/org/springframework/beans/factory/config/ConfigurableBeanFactory.html) exposes registered dependency relationships, which may not capture every dynamic lookup or runtime path.
* The third-party [Boot Usage project](https://github.com/dhruv-15-03/boot-usage) describes reporting starters based on auto-configurations contributing beans. This is adjacent prior art; bean contribution alone does not establish workload use or safe removability.
