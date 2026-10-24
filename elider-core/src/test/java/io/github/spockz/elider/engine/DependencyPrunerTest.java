// WHY: Exercises the core pruning contract with synthetic indexes and traces so every safety rule
// can be checked without Maven, network access, or external artifacts.

package io.github.spockz.elider.engine;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.ArtifactFileRef;
import io.github.spockz.elider.model.ElisionDecision;
import io.github.spockz.elider.model.TraceData;
import io.github.spockz.elider.scanner.ArtifactClassIndex;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

/** Verifies pruning decisions and failures using hermetic inputs. */
@SuppressWarnings({
  "PMD.TooManyMethods",
  "PMD.AvoidDuplicateLiterals",
  "PMD.UnitTestContainsTooManyAsserts",
  "PMD.AtLeastOneConstructor"
})
class DependencyPrunerTest {
  /** The pruner exercised by each independent policy case. */
  private final DependencyPruner pruner = new DependencyPruner();

  @Test
  void elidesUnusedEligibleJarAndReportsClassBreakdown() {
    final ArtifactFileRef used = artifact("used", "jar", "", "compile");
    final ArtifactFileRef unused = artifact("unused", "jar", "", "runtime");
    final ArtifactClassIndex index =
        index(
            Map.of(
                used, Set.of("sample.Used", "sample.AlsoUnused"), unused, Set.of("sample.Idle")));

    final ElisionDecision result = prune(List.of(used, unused), index, trace("sample.Used"));

    assertThat(result.retainedArtifacts()).containsExactlyInAnyOrder(used.coordinate());
    assertThat(result.elidedArtifacts()).containsExactlyInAnyOrder(unused.coordinate());
    assertThat(result.getRetainedClasses(used.coordinate())).containsExactly("sample.Used");
    assertThat(result.getUnusedClasses(used.coordinate())).containsExactly("sample.AlsoUnused");
    assertThat(result.getUnusedClasses(unused.coordinate())).containsExactly("sample.Idle");
    assertThat(result.totalArtifacts()).isEqualTo(2);
  }

  @Test
  void duplicateObservedClassRetainsEveryOwningArtifact() {
    final ArtifactFileRef first = artifact("first", "jar", "", "compile");
    final ArtifactFileRef second = artifact("second", "jar", "", "compile");
    final ElisionDecision result =
        prune(
            List.of(first, second),
            index(Map.of(first, Set.of("sample.Shared"), second, Set.of("sample.Shared"))),
            trace("sample.Shared"));

    assertThat(result.retainedArtifacts())
        .containsExactlyInAnyOrder(first.coordinate(), second.coordinate());
    assertThat(result.elidedArtifacts()).isEmpty();
  }

  @Test
  void retainsEmptyResourceOnlyJarsAndNonJarTypes() {
    final ArtifactFileRef empty = artifact("resources", "jar", "", "compile");
    final ArtifactFileRef pom = artifact("metadata", "pom", "", "compile");
    final ArtifactFileRef dependency = artifact("used", "jar", "", "compile");
    final ElisionDecision result =
        prune(
            List.of(empty, pom, dependency),
            index(
                Map.of(
                    empty, Set.of(), pom, Set.of("sample.Pom"), dependency, Set.of("sample.Used"))),
            trace("sample.Used"));

    assertThat(result.retainedArtifacts())
        .containsExactlyInAnyOrder(empty.coordinate(), pom.coordinate(), dependency.coordinate());
    assertThat(result.getUnusedClasses(empty.coordinate())).isEmpty();
  }

  @Test
  void preservesNonEligibleScopesUnlessConfiguredEligible() {
    final ArtifactFileRef test = artifact("test", "jar", "", "test");
    final ArtifactFileRef provided = artifact("provided", "jar", "", "provided");
    final ArtifactFileRef system = artifact("system", "jar", "", "system");
    final ArtifactFileRef unknown = artifact("unknown", "jar", "", "custom");
    final ArtifactFileRef runtime = artifact("runtime", "jar", "", "runtime");
    final ArtifactClassIndex index =
        index(
            Map.of(
                test,
                Set.of("sample.T"),
                provided,
                Set.of("sample.P"),
                system,
                Set.of("sample.S"),
                unknown,
                Set.of("sample.U"),
                runtime,
                Set.of("sample.R")));

    final ElisionDecision defaults =
        prune(List.of(test, provided, system, unknown, runtime), index, trace("sample.R"));
    final PruneConfig custom =
        new PruneConfig(Set.of(), Set.of(), Set.of("compile", "runtime", "test"));
    final ElisionDecision optedIn =
        pruner.prune(
            List.of(test, provided, system, unknown, runtime), index, trace("sample.R"), custom);

    assertThat(defaults.retainedCount()).isEqualTo(5);
    assertThat(optedIn.elidedArtifacts()).containsExactly(test.coordinate());
    assertThat(optedIn.retainedArtifacts())
        .containsExactlyInAnyOrder(
            provided.coordinate(), system.coordinate(), unknown.coordinate(), runtime.coordinate());
  }

  @Test
  void keepScopesAlwaysRetainCandidates() {
    final ArtifactFileRef scoped = artifact("scoped", "jar", "", "runtime");
    final ArtifactFileRef observed = artifact("observed", "jar", "", "compile");
    final PruneConfig config = new PruneConfig(Set.of("runtime"), Set.of());
    final ElisionDecision result =
        pruner.prune(
            List.of(scoped, observed),
            index(Map.of(scoped, Set.of("sample.S"), observed, Set.of("sample.O"))),
            trace("sample.O"),
            config);

    assertThat(result.retainedArtifacts())
        .containsExactlyInAnyOrder(scoped.coordinate(), observed.coordinate());
    assertThat(result.elidedArtifacts()).isEmpty();
  }

  @Test
  void keepArtifactsOverrideRetainsOnlyTheMatchingCoordinate() {
    final ArtifactFileRef pinned = artifact("pinned", "jar", "tests", "compile");
    final ArtifactFileRef sibling = artifact("sibling", "jar", "", "compile");
    final ArtifactFileRef observed = artifact("observed", "jar", "", "compile");
    final PruneConfig config = new PruneConfig(Set.of(), Set.of(pinned.coordinate()));
    final ElisionDecision result =
        pruner.prune(
            List.of(pinned, sibling, observed),
            index(
                Map.of(
                    pinned, Set.of("sample.Pinned"),
                    sibling, Set.of("sample.Sibling"),
                    observed, Set.of("sample.Observed"))),
            trace("sample.Observed"),
            config);

    assertThat(result.retainedArtifacts())
        .containsExactlyInAnyOrder(pinned.coordinate(), observed.coordinate());
    assertThat(result.elidedArtifacts()).containsExactlyInAnyOrder(sibling.coordinate());
  }

  @Test
  void globalExclusionsIgnoreScopeButPreserveArtifactIdentity() {
    final ArtifactCoordinate excludedCompile =
        new ArtifactCoordinate("sample", "excluded", "1.0", "jar", "tests", "compile");
    final ArtifactFileRef compile =
        new ArtifactFileRef(excludedCompile, Path.of("excluded.jar"), 1, 2);
    final ArtifactFileRef runtime =
        new ArtifactFileRef(
            new ArtifactCoordinate("sample", "excluded", "1.0", "jar", "tests", "runtime"),
            Path.of("excluded-runtime.jar"),
            1,
            2);
    final ArtifactFileRef differentType = artifact("excluded", "zip", "tests", "compile");
    final ArtifactFileRef differentClassifier = artifact("excluded", "jar", "other", "compile");
    final ArtifactFileRef differentVersion =
        new ArtifactFileRef(
            new ArtifactCoordinate("sample", "excluded", "2.0", "jar", "tests", "compile"),
            Path.of("excluded-v2.jar"),
            1,
            2);
    final ArtifactFileRef observed = artifact("observed", "jar", "", "compile");
    final PruneConfig config =
        new PruneConfig(Set.of(), Set.of(), Set.of("compile", "runtime"), Set.of(excludedCompile));
    assertThat(config.keeps(compile.coordinate())).isTrue();
    assertThat(config.keeps(runtime.coordinate())).isTrue();
    assertThat(config.keeps(differentType.coordinate())).isFalse();
    assertThat(config.keeps(differentClassifier.coordinate())).isFalse();
    assertThat(config.keeps(differentVersion.coordinate())).isFalse();
    final ElisionDecision result =
        pruner.prune(
            List.of(
                compile, runtime, differentType, differentClassifier, differentVersion, observed),
            index(
                Map.of(
                    compile, Set.of("sample.ExcludedCompile"),
                    runtime, Set.of("sample.ExcludedRuntime"),
                    differentType, Set.of("sample.DifferentType"),
                    differentClassifier, Set.of("sample.DifferentClassifier"),
                    differentVersion, Set.of("sample.DifferentVersion"),
                    observed, Set.of("sample.Observed"))),
            trace("sample.Observed"),
            config);

    assertThat(result.retainedArtifacts())
        .containsExactlyInAnyOrder(
            compile.coordinate(),
            runtime.coordinate(),
            differentType.coordinate(),
            observed.coordinate());
    assertThat(result.elidedArtifacts())
        .containsExactlyInAnyOrder(differentClassifier.coordinate(), differentVersion.coordinate());
  }

  @Test
  void emptyTraceAndNoSuppliedClassMatchAreRejected() {
    final ArtifactFileRef artifact = artifact("dependency", "jar", "", "compile");
    final ArtifactClassIndex index = index(Map.of(artifact, Set.of("sample.Present")));

    assertThatIllegalArgumentException()
        .isThrownBy(() -> prune(List.of(artifact), index, TraceData.empty()))
        .withMessageContaining("empty normalized");
    assertThatIllegalArgumentException()
        .isThrownBy(() -> prune(List.of(artifact), index, trace("external.Only")))
        .withMessageContaining("no observed class matches");
  }

  @Test
  void missingIndexForEligibleCandidateIsRejected() {
    final ArtifactFileRef missing = artifact("missing", "jar", "", "compile");
    final ArtifactFileRef indexed = artifact("indexed", "jar", "", "compile");
    final ArtifactClassIndex index = index(Map.of(indexed, Set.of("sample.Observed")));

    assertThatIllegalArgumentException()
        .isThrownBy(() -> prune(List.of(indexed, missing), index, trace("sample.Observed")))
        .withMessageContaining("Missing class index entry");
  }

  @Test
  void rejectsDifferentFilesForSameFullCoordinate() {
    final ArtifactFileRef first = artifact("same", "jar", "tests", "compile", Path.of("first.jar"));
    final ArtifactFileRef second =
        artifact("same", "jar", "tests", "compile", Path.of("second.jar"));

    assertThatIllegalArgumentException()
        .isThrownBy(
            () ->
                prune(
                    List.of(first, second),
                    index(Map.of(first, Set.of("sample.X"), second, Set.of("sample.X"))),
                    trace("sample.X")))
        .withMessageContaining("Conflicting artifact files");
  }

  @Test
  void keepsClassifierAndTypeAsDistinctArtifactIdentitiesAndOutputsAreImmutable() {
    final ArtifactFileRef main = artifact("lib", "jar", "", "compile");
    final ArtifactFileRef tests = artifact("lib", "jar", "tests", "compile");
    final ArtifactFileRef zip = artifact("lib", "zip", "", "compile");
    final ElisionDecision result =
        prune(
            List.of(main, tests, zip),
            index(
                Map.of(
                    main,
                    Set.of("sample.Main"),
                    tests,
                    Set.of("sample.Tests"),
                    zip,
                    Set.of("sample.Zip"))),
            trace("sample.Main"));

    assertThat(result.retainedArtifacts())
        .containsExactlyInAnyOrder(main.coordinate(), zip.coordinate());
    assertThat(result.elidedArtifacts()).containsExactlyInAnyOrder(tests.coordinate());
    assertThat(result.retainedClassesPerArtifact())
        .isEqualTo(
            Map.of(
                main.coordinate(), Set.of("sample.Main"),
                tests.coordinate(), Set.of(),
                zip.coordinate(), Set.of()));
    assertThat(result.unusedClassesPerArtifact())
        .isEqualTo(
            Map.of(
                main.coordinate(), Set.of(),
                tests.coordinate(), Set.of("sample.Tests"),
                zip.coordinate(), Set.of("sample.Zip")));
    assertThatThrownBy(() -> result.retainedClassesPerArtifact().put(main.coordinate(), Set.of()))
        .isInstanceOf(UnsupportedOperationException.class);
    assertThatThrownBy(() -> result.unusedClassesPerArtifact().put(main.coordinate(), Set.of()))
        .isInstanceOf(UnsupportedOperationException.class);
    assertThatThrownBy(
            () -> result.retainedClassesPerArtifact().get(main.coordinate()).add("sample.Other"))
        .isInstanceOf(UnsupportedOperationException.class);
    assertThatThrownBy(() -> result.unusedClassesPerArtifact().get(tests.coordinate()).clear())
        .isInstanceOf(UnsupportedOperationException.class);
    assertThatThrownBy(() -> result.elidedArtifacts().add(main.coordinate()))
        .isInstanceOf(UnsupportedOperationException.class);
    assertThat(result.retainedArtifacts()).doesNotContain(tests.coordinate());
  }

  @Test
  void scopeDoesNotCollapseClassifierOrTypeCoordinates() {
    final ArtifactCoordinate firstCoordinate =
        new ArtifactCoordinate("g", "a", "1", "jar", "one", "compile");
    final ArtifactCoordinate secondCoordinate =
        new ArtifactCoordinate("g", "a", "1", "jar", "two", "compile");
    final ArtifactCoordinate differentTypeCoordinate =
        new ArtifactCoordinate("g", "a", "1", "zip", "one", "compile");
    assertThat(Set.of(firstCoordinate, secondCoordinate, differentTypeCoordinate)).hasSize(3);
  }

  private ElisionDecision prune(
      final List<ArtifactFileRef> artifacts,
      final ArtifactClassIndex index,
      final TraceData trace) {
    return pruner.prune(artifacts, index, trace, new PruneConfig());
  }

  private static TraceData trace(final String... names) {
    return TraceData.of(Set.of(names));
  }

  private static ArtifactClassIndex index(final Map<ArtifactFileRef, Set<String>> classes) {
    return new ArtifactClassIndex(classes);
  }

  private static ArtifactFileRef artifact(
      final String artifactId, final String type, final String classifier, final String scope) {
    return artifact(artifactId, type, classifier, scope, Path.of(artifactId + "." + type));
  }

  private static ArtifactFileRef artifact(
      final String artifactId,
      final String type,
      final String classifier,
      final String scope,
      final Path path) {
    return new ArtifactFileRef(
        new ArtifactCoordinate("sample", artifactId, "1.0", type, classifier, scope), path, 1, 2);
  }
}
