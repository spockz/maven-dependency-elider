<!-- WHY: Answers practical user questions about configuring elision, interpreting its results, and understanding supported boundaries. -->
# User FAQ

This page covers user-facing configuration, outcomes, compatibility limits, and practical concerns. For implementation rationale, benchmark evidence, and contributor decisions, see the [Contributor Decision Register and Engineering FAQ](contributor-decisions-and-faq.md).

## Using Elision

### What does the plugin remove?

Elision can remove unused dependency artifacts from the current Maven build and can optionally remove unused classes from retained dependency JARs. It does not edit your POM or rewrite dependency declarations.

### How do I enable elision?

Configure a supported trace file and set `-Delide.skip=false`. See [Maven plugin usage](plugin-usage.md) for trace formats, JAR trimming options, and examples.

For the repository examples, use `-Delide.mode=baseline` or `-Delide.mode=elision` with the same POM. `elision` activates the example profile; `baseline` is the default. This makes it easy to compare the two packaged outputs without maintaining separate POMs.

### How can I see the dependencies effective after elision?

Run the lifecycle phase and tree goal in one invocation if you want the elider to execute before the report:

```sh
./mvnw -Delide.skip=false -Delide.traceFiles=/path/to/trace.log \
  initialize org.apache.maven.plugins:maven-dependency-plugin:3.8.1:tree
```

The goal is for Maven's standard `dependency:tree` to show the post-elision effective dependencies. The current integration does not do that yet: the Basic example's tree lists Commons Codec although the elided classpath and package omit it. Until resolver integration changes, inspect the effective classpath or final package for the actual inventory. A separate elider report is planned to show the original dependency paths with each artifact marked retained or elided. See [RQ-0006](research/RQ-0006-maven-artifact-view-consistency-and-early-resolution-hooks.md).

### How can I keep a dependency JAR unchanged?

Set `elide.trimSkipArtifacts` to the exact resolved coordinate, such as `groupId:artifactId:version:jar:`. The JAR remains byte-identical and is protected from whole-artifact elision. Its classes can still cause linked classes in other trim candidates to be retained. See [Maven plugin usage](plugin-usage.md) for the Spring example.

### What happens if a dependency contains multi-release implementation classes?

That JAR is kept byte-identical and skipped as a trim target with a warning. Other supported JARs can still be trimmed. Set `-Delide.failOnUnsupportedMultiRelease=true` if encountering such a JAR should fail the build.

### What if my application runs on a different JDK than Maven?

Multi-release analysis currently uses the JDK feature release running Maven. If the deployed application uses a different JDK, its selected multi-release implementation has not been verified by that analysis. Run analysis with the deployment JDK or configure affected JARs for pass-through until that runtime is covered.

### What if generated sources are not available before `INITIALIZE`?

Leave `elide.sourceRootsComplete=false`, the default. This conservatively keeps compile-visible JARs and their classes available for trimming. Set it to `true` only when all production and generated sources are available before the elider runs and no later generator adds compile references.

### What happens to JARs with a root `module-info.class`?

On the classpath, such JARs are kept byte-identical with a warning. Set `-Delide.failOnUnsupportedModuleInfo=true` to fail instead. JPMS module-path behavior is not supported.

### What happens when the plugin encounters metadata or an archive layout it does not understand?

It fails before changing Maven artifact pointers rather than assuming unknown metadata is unused. Multi-release and root-module-info JARs have the explicit pass-through policies described above, with strict failure options available.

### Does removing classes make a vulnerability finding go away?

Not necessarily. Many vulnerability tools report by artifact coordinates and version, even when some classes have been removed. Inspect and scan the final packaged artifact, and assess the advisory's affected code and exploit conditions separately.

## Compatibility and Performance

### Is Java 25 class-file analysis supported?

No, not with the currently pinned ProGuard Core 9.1.10. The validated example toolchain is GraalVM JDK 21. A newer Maven runtime analyzing dependencies compiled to an older class-file version is a separate compatibility case.

### How much build time does elision add?

One local `clean verify` run measured Basic at 2.256 seconds without elision and 4.218 seconds with it; Spring Boot measured 4.072 seconds and 75.933 seconds, respectively. These are single-run observations, not stable performance guarantees. The Spring result shows that the current trimming path can add substantial time. Elision remains under active development and should not be used to remove dependencies from production builds.
