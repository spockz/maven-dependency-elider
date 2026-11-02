// WHY: Verifies schema-one captures preserve original declarations as detached immutable values.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.apache.maven.model.Dependency;
import org.apache.maven.model.Exclusion;
import org.apache.maven.model.Model;
import org.apache.maven.project.MavenProject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Covers capture provenance, immutability, and payload validation. */
@SuppressWarnings({
  "PMD.AtLeastOneConstructor",
  "PMD.CommentDefaultAccessModifier",
  "PMD.TooManyMethods",
  "PMD.AvoidDuplicateLiterals"
})
final class BanishedDependencyCaptureStoreTest {
  /** Group shared by the Maven model fixtures. */
  private static final String GROUP_ID = "org.example";

  /** Artifact component used by the synthetic Maven project. */
  private static final String ARTIFACT_ID = "consumer";

  /** Version shared by default dependency fixtures. */
  private static final String DEFAULT_VERSION = "1.0";

  /** Scope shared by default dependency fixtures. */
  private static final String DEFAULT_SCOPE = "compile";

  /** Dependency artifact used by capture source comparisons. */
  private static final String LIBRARY_ARTIFACT = "library";

  /** Ban coordinate used by capture fixtures. */
  private static final String BAN = GROUP_ID + ":banned";

  /** Execution identifier used in lifecycle policy fixtures. */
  private static final String EXECUTION_ID = "run-elide";

  /** Lifecycle phase used in execution policy fixtures. */
  private static final String INITIALIZE_PHASE = "initialize";

  /** Temporary project directory used for detached identity data. */
  @TempDir Path temporaryDirectory;

  @Test
  void capturesEffectiveAndOriginalDeclarationsWithExclusionProvenance() {
    final MavenProject project = project();
    final Dependency activeDependency =
        dependency(LIBRARY_ARTIFACT, DEFAULT_VERSION, DEFAULT_SCOPE);
    activeDependency.addExclusion(exclusion("legacy", "excluded"));
    final Dependency originalDependency = dependency("raw", "2.0", "runtime");
    final Dependency managedDependency = dependency("managed", "3.0", "provided");
    final Dependency directProfileDependency = dependency("profiled", "4.0", DEFAULT_SCOPE);
    project.setDependencies(List.of(activeDependency));
    final Model original = new Model();
    original.setDependencies(List.of(originalDependency));
    final org.apache.maven.model.DependencyManagement originalManagement =
        new org.apache.maven.model.DependencyManagement();
    originalManagement.setDependencies(List.of(managedDependency));
    original.setDependencyManagement(originalManagement);
    project.setOriginalModel(original);
    final org.apache.maven.model.Profile activeProfile = new org.apache.maven.model.Profile();
    activeProfile.setId("local-profile");
    activeProfile.setDependencies(List.of(directProfileDependency));
    project.setActiveProfiles(List.of(activeProfile));

    final BanishedDependencyOriginalModel captured =
        BanishedDependencyOriginalModel.capture(
            project,
            List.of(executionPolicy(EXECUTION_ID, INITIALIZE_PHASE, List.of(BAN))),
            List.of(BAN));

    assertAll(
        "capture preserves distinct declaration sources",
        () ->
            assertThat(captured.effectiveDependencies())
                .extracting(BanishedDependencyOriginalModel.DependencyEntry::provenance)
                .containsExactly("effective-dependencies"),
        () ->
            assertThat(captured.effectiveDependencies().getFirst().exclusions())
                .containsExactly(
                    new BanishedDependencyOriginalModel.ExclusionEntry("legacy", "excluded")),
        () ->
            assertThat(captured.originalDependencies())
                .extracting(BanishedDependencyOriginalModel.DependencyEntry::provenance)
                .containsExactly(
                    "original-model-dependencies", "active-profile:local-profile:dependencies"),
        () -> assertThat(captured.effectiveManagement()).isEmpty(),
        () ->
            assertThat(captured.originalManagement())
                .extracting(BanishedDependencyOriginalModel.DependencyEntry::provenance)
                .containsExactly("original-model-management"));
  }

  @Test
  void schemaOnePayloadRoundTripsAndOnlyContainsJdkValues() {
    final BanishedDependencyOriginalModel capture =
        BanishedDependencyOriginalModel.capture(
            project(), List.of(executionPolicy("default-cli", "cli", List.of(BAN))), List.of(BAN));
    final BanishedDependencyCaptureStore store =
        BanishedDependencyCaptureStore.empty().withModel(capture);

    final Map<String, Object> payload = store.toPayload();
    final BanishedDependencyCaptureStore restored =
        BanishedDependencyCaptureStore.fromPayload(payload);

    assertAll(
        "payload round-trips as immutable JDK-only values",
        () -> assertThat(payload.get("schemaVersion")).isEqualTo(1),
        () ->
            assertThat(payload.values())
                .allSatisfy(BanishedDependencyCaptureStoreTest::assertJdkValue),
        () -> assertThat(restored.find(capture.project())).isEqualTo(capture),
        () ->
            assertThatThrownBy(() -> restored.projects().clear())
                .isInstanceOf(UnsupportedOperationException.class));
  }

  @Test
  void sourceFingerprintChangesWhenEffectiveOrOriginalDeclarationsChange() {
    final MavenProject firstProject = project();
    firstProject.setDependencies(
        List.of(dependency(LIBRARY_ARTIFACT, DEFAULT_VERSION, DEFAULT_SCOPE)));
    final MavenProject changedProject = project();
    changedProject.setDependencies(List.of(dependency(LIBRARY_ARTIFACT, "2.0", DEFAULT_SCOPE)));
    final List<BanishedDependencyOriginalModel.ExecutionPolicy> executions =
        List.of(executionPolicy(EXECUTION_ID, INITIALIZE_PHASE, List.of(BAN)));

    final BanishedDependencyOriginalModel first =
        BanishedDependencyOriginalModel.capture(firstProject, executions, List.of(BAN));
    final BanishedDependencyOriginalModel changed =
        BanishedDependencyOriginalModel.capture(changedProject, executions, List.of(BAN));

    assertThat(first.sourceFingerprint()).isNotEqualTo(changed.sourceFingerprint());
  }

  @Test
  @SuppressWarnings("PMD.UseConcurrentHashMap")
  void rejectsUnsupportedSchemaAndUnknownPayloadFields() {
    final Map<String, Object> unsupported = Map.of("schemaVersion", 2, "projects", Map.of());
    final Map<String, Object> unexpected =
        new HashMap<>(Map.of("schemaVersion", 1, "projects", Map.of()));
    unexpected.put("legacyAlias", Map.of());
    assertAll(
        "unsupported schema and unknown fields are rejected",
        () ->
            assertThatThrownBy(() -> BanishedDependencyCaptureStore.fromPayload(unsupported))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("unsupported"),
        () ->
            assertThatThrownBy(() -> BanishedDependencyCaptureStore.fromPayload(unexpected))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("fields do not match"));
  }

  @Test
  @SuppressWarnings("PMD.UseConcurrentHashMap")
  void rejectsTamperedCaptureFingerprint() {
    final BanishedDependencyOriginalModel capture =
        BanishedDependencyOriginalModel.capture(project(), List.of(), List.of());
    final Map<String, Object> payload =
        BanishedDependencyCaptureStore.empty().withModel(capture).toPayload();
    final Map<?, ?> projects = (Map<?, ?>) payload.get("projects");
    final String key = BanishedDependencyCaptureStore.projectKey(capture.project());
    final Map<?, ?> row = (Map<?, ?>) projects.get(key);
    final Map<Object, Object> tampered = new HashMap<>(row);
    tampered.put("sourceFingerprint", "0".repeat(64));
    assertThatThrownBy(
            () ->
                BanishedDependencyCaptureStore.fromPayload(
                    Map.of("schemaVersion", 1, "projects", Map.of(key, tampered))))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("fingerprint");
  }

  @Test
  void rejectsImpossibleOriginWithRecomputedFingerprint() {
    final MavenProject project = project();
    project.setDependencies(List.of(dependency(LIBRARY_ARTIFACT, DEFAULT_VERSION, DEFAULT_SCOPE)));
    final BanishedDependencyOriginalModel capture =
        BanishedDependencyOriginalModel.capture(project, List.of(), List.of());
    assertRejectsOrigin(capture, "UNKNOWN", "LOCAL", "");
  }

  @Test
  void rejectsInactiveProfileWithRecomputedFingerprint() {
    final MavenProject project = project();
    final Dependency dependency = dependency(LIBRARY_ARTIFACT, DEFAULT_VERSION, DEFAULT_SCOPE);
    final org.apache.maven.model.InputSource source = new org.apache.maven.model.InputSource();
    source.setModelId("source-model");
    source.setLocation("pom.xml");
    dependency.setLocation("", new org.apache.maven.model.InputLocation(1, 2, source));
    project.setDependencies(List.of(dependency));
    final Model raw = new Model();
    raw.setDependencies(List.of(dependency));
    project.setOriginalModel(raw);
    project.setInjectedProfileIds("source-model", List.of("active"));
    final BanishedDependencyOriginalModel capture =
        BanishedDependencyOriginalModel.capture(project, List.of(), List.of());
    assertRejectsOrigin(capture, "LOCAL", "LOCAL_PROFILE", "inactive");
  }

  @SuppressWarnings("PMD.UseConcurrentHashMap")
  private static void assertRejectsOrigin(
      final BanishedDependencyOriginalModel capture,
      final String oldKind,
      final String newKind,
      final String profileId) {
    final Map<String, Object> payload =
        BanishedDependencyCaptureStore.empty().withModel(capture).toPayload();
    final String key = BanishedDependencyCaptureStore.projectKey(capture.project());
    final Map<?, ?> projects = (Map<?, ?>) payload.get("projects");
    final Map<Object, Object> row = new HashMap<>((Map<?, ?>) projects.get(key));
    final Map<Object, Object> provenance =
        new HashMap<>((Map<?, ?>) row.get("exclusionProvenance"));
    final List<?> declarations = (List<?>) provenance.get("dependencies");
    final Map<Object, Object> declaration = new HashMap<>((Map<?, ?>) declarations.getFirst());
    final Map<Object, Object> origin = new HashMap<>((Map<?, ?>) declaration.get("origin"));
    origin.put("kind", newKind);
    origin.put("profileId", profileId);
    declaration.put("origin", origin);
    provenance.put("dependencies", List.of(declaration));
    row.put("exclusionProvenance", provenance);
    final List<String> fields = new ArrayList<>(capture.sourceFingerprintFields());
    final int kindIndex = fields.indexOf(oldKind);
    fields.set(kindIndex, newKind);
    fields.set(kindIndex + 5, profileId);
    row.put("sourceFingerprint", MavenElisionGraphBinding.sha256(fields));
    assertThatThrownBy(
            () ->
                BanishedDependencyCaptureStore.fromPayload(
                    Map.of("schemaVersion", 1, "projects", Map.of(key, row))))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("provenance");
  }

  @Test
  @SuppressWarnings("PMD.LawOfDemeter")
  void expectedInjectionPreservesUserExclusionsAndRejectsChangedSources() {
    final Dependency dependency = dependency(LIBRARY_ARTIFACT, DEFAULT_VERSION, DEFAULT_SCOPE);
    dependency.addExclusion(exclusion("user", "exclusion"));
    final MavenProject project = project();
    project.setDependencies(List.of(dependency));
    final List<BanishedDependencyOriginalModel.ExecutionPolicy> executions =
        List.of(executionPolicy(EXECUTION_ID, INITIALIZE_PHASE, List.of(BAN)));
    final List<String> bans = List.of(BAN);
    final BanishedDependencyOriginalModel original =
        BanishedDependencyOriginalModel.capture(project, executions, bans);
    final List<BanishedDependencyOriginalModel.DependencyEntry> changedDependencies =
        original.withExpectedInjections().effectiveDependencies();
    final BanishedDependencyOriginalModel current =
        new BanishedDependencyOriginalModel(
            original.project(),
            executions,
            bans,
            changedDependencies,
            original.originalDependencies(),
            original.effectiveManagement(),
            original.originalManagement(),
            original.exclusionProvenance(),
            original.sourceFingerprint());
    final BanishedDependencyOriginalModel.DependencyEntry originalEntry =
        original.effectiveDependencies().getFirst();
    final BanishedDependencyOriginalModel.DependencyEntry changedEntry =
        new BanishedDependencyOriginalModel.DependencyEntry(
            originalEntry.provenance(),
            originalEntry.ordinal(),
            originalEntry.groupId(),
            originalEntry.artifactId(),
            "9.0",
            originalEntry.type(),
            originalEntry.classifier(),
            originalEntry.scope(),
            originalEntry.optional(),
            originalEntry.systemPath(),
            changedDependencies.getFirst().exclusions());
    final BanishedDependencyOriginalModel changedSource =
        new BanishedDependencyOriginalModel(
            original.project(),
            executions,
            bans,
            List.of(changedEntry),
            original.originalDependencies(),
            original.effectiveManagement(),
            original.originalManagement(),
            original.exclusionProvenance(),
            original.sourceFingerprint());
    final BanishedDependencyOriginalModel changedPolicy =
        new BanishedDependencyOriginalModel(
            original.project(),
            List.of(executionPolicy(EXECUTION_ID, INITIALIZE_PHASE, List.of(GROUP_ID + ":other"))),
            List.of(GROUP_ID + ":other"),
            changedDependencies,
            original.originalDependencies(),
            original.effectiveManagement(),
            original.originalManagement(),
            original.exclusionProvenance(),
            original.sourceFingerprint());
    dependency.addExclusion(exclusion(GROUP_ID, "banned"));
    final BanishedDependencyOriginalModel liveAfterInjection =
        BanishedDependencyOriginalModel.capture(project, executions, bans);
    dependency
        .getExclusions()
        .getFirst()
        .setLocation("", new org.apache.maven.model.InputLocation(1, 2));
    final BanishedDependencyOriginalModel changedOrigin =
        BanishedDependencyOriginalModel.capture(project, executions, bans);

    assertAll(
        "identical captures reapply idempotently and changed source or policy is rejected",
        () -> assertThat(original.matchesCurrentModel(current)).isTrue(),
        () -> assertThat(original.matchesCurrentModel(liveAfterInjection)).isTrue(),
        () -> assertThat(original.matchesCurrentModel(changedOrigin)).isFalse(),
        () ->
            assertThat(original.withExpectedInjections().sourceFingerprint())
                .isEqualTo(original.sourceFingerprint()),
        () ->
            assertThat(changedDependencies.getFirst().exclusions())
                .containsExactly(
                    new BanishedDependencyOriginalModel.ExclusionEntry("user", "exclusion"),
                    new BanishedDependencyOriginalModel.ExclusionEntry(GROUP_ID, "banned")),
        () -> assertThat(original.matchesCurrentModel(changedSource)).isFalse(),
        () -> assertThat(original.matchesCurrentModel(changedPolicy)).isFalse(),
        () -> assertThat(original.matchesCurrentModel(null)).isFalse());
  }

  private MavenProject project() {
    final Model model = new Model();
    model.setGroupId(GROUP_ID);
    model.setArtifactId(ARTIFACT_ID);
    model.setVersion("1.0");
    final MavenProject project = new MavenProject(model);
    project.setFile(temporaryDirectory.resolve("pom.xml").toFile());
    return project;
  }

  private static BanishedDependencyOriginalModel.ExecutionPolicy executionPolicy(
      final String executionId, final String phase, final List<String> bans) {
    return new BanishedDependencyOriginalModel.ExecutionPolicy(
        executionId, "elide", "1.0", phase, "LIFECYCLE", bans);
  }

  private static Dependency dependency(
      final String artifactId, final String version, final String scope) {
    final Dependency dependency = new Dependency();
    dependency.setGroupId(GROUP_ID);
    dependency.setArtifactId(artifactId);
    dependency.setVersion(version);
    dependency.setType("jar");
    dependency.setScope(scope);
    return dependency;
  }

  private static Exclusion exclusion(final String groupId, final String artifactId) {
    final Exclusion exclusion = new Exclusion();
    exclusion.setGroupId(groupId);
    exclusion.setArtifactId(artifactId);
    return exclusion;
  }

  private static void assertJdkValue(final Object value) {
    if (value == null) {
      return;
    }
    assertThat(value).isInstanceOfAny(Map.class, List.class, String.class, Integer.class);
    if (value instanceof Map<?, ?> map) {
      map.values().forEach(BanishedDependencyCaptureStoreTest::assertJdkValue);
    }
    if (value instanceof List<?> list) {
      list.forEach(BanishedDependencyCaptureStoreTest::assertJdkValue);
    }
  }
}
