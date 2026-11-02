// WHY: Exercises exclusion origins using Maven's actual model merge and location tracking.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import org.apache.maven.model.Dependency;
import org.apache.maven.model.Exclusion;
import org.apache.maven.model.Parent;
import org.apache.maven.model.Profile;
import org.apache.maven.model.Repository;
import org.apache.maven.model.building.DefaultModelBuilderFactory;
import org.apache.maven.model.building.DefaultModelBuildingRequest;
import org.apache.maven.model.building.FileModelSource;
import org.apache.maven.model.building.ModelBuildingRequest;
import org.apache.maven.model.building.ModelSource;
import org.apache.maven.model.resolution.ModelResolver;
import org.apache.maven.model.resolution.UnresolvableModelException;
import org.apache.maven.project.MavenProject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

@SuppressWarnings({
  "PMD.AtLeastOneConstructor",
  "PMD.CommentDefaultAccessModifier",
  "PMD.CommentRequired",
  "PMD.UseExplicitTypes",
  "PMD.AvoidDuplicateLiterals"
})
final class ExclusionProvenanceCaptureTest {
  @TempDir Path directory;

  @Test
  void interpolatedProjectVersionPreservesLocalOrigins() throws Exception {
    final Path pom = directory.resolve("pom.xml");
    Files.writeString(
        pom,
        """
        <project xmlns="http://maven.apache.org/POM/4.0.0">
          <modelVersion>4.0.0</modelVersion>
          <groupId>example</groupId><artifactId>consumer</artifactId><version>${revision}</version>
          <properties><revision>1</revision></properties>
          <dependencyManagement><dependencies><dependency>
            <groupId>libs</groupId><artifactId>managed</artifactId><version>1</version>
            <exclusions><exclusion><groupId>excluded</groupId><artifactId>managed</artifactId></exclusion></exclusions>
          </dependency></dependencies></dependencyManagement>
          <dependencies><dependency><groupId>libs</groupId><artifactId>direct</artifactId><version>1</version>
            <exclusions><exclusion><groupId>excluded</groupId><artifactId>direct</artifactId></exclusion></exclusions>
          </dependency><dependency><groupId>libs</groupId><artifactId>managed</artifactId></dependency></dependencies>
        </project>
        """);
    final DefaultModelBuildingRequest request = new DefaultModelBuildingRequest();
    request
        .setPomFile(pom.toFile())
        .setLocationTracking(true)
        .setSystemProperties(System.getProperties());
    final var result = new DefaultModelBuilderFactory().newInstance().build(request);
    final MavenProject project = new MavenProject(result.getEffectiveModel());
    project.setOriginalModel(result.getRawModel(result.getModelIds().getFirst()));
    final var snapshot = ExclusionProvenanceCapture.capture(project);
    final var direct = snapshot.dependencies().getFirst();
    final var managed = snapshot.dependencies().get(1);
    assertAll(
        () -> assertThat(project.getVersion()).isEqualTo("1"),
        () -> assertThat(snapshot.diagnostics()).isEmpty(),
        () ->
            assertThat(direct.reference().origin().modelId())
                .isEqualTo("example:consumer:${revision}"),
        () -> assertThat(direct.reference().origin().kind()).isEqualTo("LOCAL"),
        () -> assertThat(direct.exclusions().getFirst().origin().kind()).isEqualTo("LOCAL"),
        () -> assertThat(managed.reference().origin().kind()).isEqualTo("LOCAL"),
        () ->
            assertThat(managed.exclusions().getFirst().origin().kind())
                .isEqualTo("LOCAL_MANAGEMENT"));
  }

  @Test
  void countsEffectiveRowsOnceAndExcludesWildcards() {
    final var origin = new ExclusionRecommendations.Origin("LOCAL", "g:a:1", "pom.xml", 1, 2, "");
    final var exact =
        new ExclusionRecommendations.Exclusion(
            new ExclusionRecommendations.Coordinate("excluded", "shared"), origin);
    final var wildcard =
        new ExclusionRecommendations.Exclusion(
            new ExclusionRecommendations.Coordinate("excluded", "part*"), origin);
    final var first =
        new ExclusionRecommendations.Declaration(
            new ExclusionRecommendations.Reference(0, "libs", "one", "jar", "", origin),
            List.of(exact, exact, wildcard));
    final var second =
        new ExclusionRecommendations.Declaration(
            new ExclusionRecommendations.Reference(1, "libs", "one", "test-jar", "tests", origin),
            List.of(exact, wildcard));
    final var result =
        ExclusionRecommendations.collect(
            new ExclusionRecommendations.Snapshot(
                List.of(first, second), List.of(), Map.of(), List.of()));
    assertAll(
        () -> assertThat(result.candidates()).hasSize(1),
        () -> assertThat(result.candidates().getFirst().count()).isEqualTo(2),
        () ->
            assertThat(result.candidates().getFirst().declarations())
                .extracting(observation -> observation.declaration().type())
                .containsExactly("jar", "test-jar"),
        () ->
            assertThat(result.candidates().getFirst().declarations().getFirst().exclusionOrigins())
                .containsExactly(origin));
  }

  @Test
  void missingLocationsRemainExplicitlyIncomplete() {
    final MavenProject project = new MavenProject();
    final Dependency dependency = new Dependency();
    dependency.setGroupId("group");
    dependency.setArtifactId("dependency");
    final Exclusion exclusion = new Exclusion();
    exclusion.setGroupId("excluded");
    exclusion.setArtifactId("artifact");
    dependency.addExclusion(exclusion);
    project.setDependencies(List.of(dependency));
    final ExclusionRecommendations.Snapshot snapshot = ExclusionProvenanceCapture.capture(project);
    assertAll(
        () ->
            assertThat(snapshot.diagnostics()).contains("Original model locations are unavailable"),
        () ->
            assertThat(snapshot.dependencies().getFirst().reference().origin().kind())
                .isEqualTo("UNKNOWN"),
        () ->
            assertThat(snapshot.dependencies().getFirst().exclusions().getFirst().origin().kind())
                .isEqualTo("UNKNOWN"));
  }

  @Test
  void rejectsMalformedProvenancePayload() {
    assertAll(
        () ->
            assertThatThrownBy(
                    () ->
                        ExclusionProvenancePayload.decode(
                            Map.of(
                                "dependencies",
                                List.of(),
                                "management",
                                List.of(),
                                "diagnostics",
                                List.of(),
                                "extra",
                                "")))
                .isInstanceOf(IllegalStateException.class),
        () ->
            assertThatThrownBy(
                    () ->
                        ExclusionProvenancePayload.decode(
                            Map.of(
                                "dependencies",
                                List.of(Map.of()),
                                "management",
                                List.of(),
                                "diagnostics",
                                List.of())))
                .isInstanceOf(IllegalStateException.class));
  }

  @Test
  @SuppressWarnings("PMD.UseConcurrentHashMap")
  void rejectsImpossibleOriginsAndUnverifiedProfiles() {
    final Map<String, Object> known =
        Map.of(
            "kind",
            "LOCAL",
            "modelId",
            "g:a:1",
            "source",
            "pom.xml",
            "line",
            1,
            "column",
            2,
            "profileId",
            "");
    final Map<String, Object> blankModel = new java.util.HashMap<>(known);
    blankModel.put("modelId", "");
    final Map<String, Object> badLine = new java.util.HashMap<>(known);
    badLine.put("line", 0);
    final Map<String, Object> forgedProfile = new java.util.HashMap<>(known);
    forgedProfile.put("kind", "LOCAL_PROFILE");
    forgedProfile.put("profileId", "not-active");
    final Map<String, Object> nonProfile = new java.util.HashMap<>(known);
    nonProfile.put("profileId", "active");
    final Map<String, Object> unknown = new java.util.HashMap<>(known);
    unknown.put("kind", "UNKNOWN");
    assertAll(
        () ->
            assertThatThrownBy(
                    () ->
                        ExclusionProvenancePayload.decode(
                            payloadWithOrigin(blankModel, Map.of(), List.of())))
                .isInstanceOf(IllegalStateException.class),
        () ->
            assertThatThrownBy(
                    () ->
                        ExclusionProvenancePayload.decode(
                            payloadWithOrigin(badLine, Map.of(), List.of())))
                .isInstanceOf(IllegalStateException.class),
        () ->
            assertThatThrownBy(
                    () ->
                        ExclusionProvenancePayload.decode(
                            payloadWithOrigin(
                                forgedProfile, Map.of("g:a:1", List.of("active")), List.of())))
                .isInstanceOf(IllegalStateException.class),
        () ->
            assertThatThrownBy(
                    () ->
                        ExclusionProvenancePayload.decode(
                            payloadWithOrigin(
                                nonProfile, Map.of("g:a:1", List.of("active")), List.of())))
                .isInstanceOf(IllegalStateException.class),
        () ->
            assertThatThrownBy(
                    () ->
                        ExclusionProvenancePayload.decode(
                            payloadWithOrigin(unknown, Map.of(), List.of())))
                .isInstanceOf(IllegalStateException.class));
  }

  private static Map<String, Object> payloadWithOrigin(
      final Map<String, Object> origin,
      final Map<String, List<String>> profiles,
      final List<String> diagnostics) {
    return Map.of(
        "dependencies",
        List.of(
            Map.of(
                "ordinal",
                0,
                "groupId",
                "g",
                "artifactId",
                "a",
                "type",
                "jar",
                "classifier",
                "",
                "origin",
                origin,
                "exclusions",
                List.of())),
        "management",
        List.of(),
        "activeProfiles",
        profiles,
        "diagnostics",
        diagnostics);
  }

  @Test
  @SuppressWarnings("PMD.LawOfDemeter")
  void importedBomLocationsAreReportedAsIncompleteWithoutRawBomProvenance() throws Exception {
    final Path bom = directory.resolve("bom.xml");
    Files.writeString(
        bom,
        """
        <project xmlns="http://maven.apache.org/POM/4.0.0">
          <modelVersion>4.0.0</modelVersion>
          <groupId>example</groupId><artifactId>exclusions-bom</artifactId><version>1</version><packaging>pom</packaging>
          <dependencyManagement><dependencies>
            <dependency><groupId>libs</groupId><artifactId>a</artifactId><version>1</version>
              <exclusions><exclusion><groupId>excluded</groupId><artifactId>shared</artifactId></exclusion></exclusions></dependency>
            <dependency><groupId>libs</groupId><artifactId>b</artifactId><version>1</version>
              <exclusions><exclusion><groupId>excluded</groupId><artifactId>shared</artifactId></exclusion></exclusions></dependency>
          </dependencies></dependencyManagement>
        </project>
        """);
    final Path pom = directory.resolve("pom.xml");
    Files.writeString(
        pom,
        """
        <project xmlns="http://maven.apache.org/POM/4.0.0">
          <modelVersion>4.0.0</modelVersion>
          <groupId>example</groupId><artifactId>consumer</artifactId><version>1</version>
          <dependencyManagement><dependencies><dependency><groupId>example</groupId>
            <artifactId>exclusions-bom</artifactId><version>1</version><type>pom</type><scope>import</scope>
          </dependency></dependencies></dependencyManagement>
          <dependencies><dependency><groupId>libs</groupId><artifactId>a</artifactId></dependency>
            <dependency><groupId>libs</groupId><artifactId>b</artifactId></dependency></dependencies>
        </project>
        """);
    final DefaultModelBuildingRequest request = new DefaultModelBuildingRequest();
    request
        .setPomFile(pom.toFile())
        .setLocationTracking(true)
        .setModelResolver(new BomResolver(bom))
        .setSystemProperties(System.getProperties());
    final var result = new DefaultModelBuilderFactory().newInstance().build(request);
    final MavenProject project = new MavenProject(result.getEffectiveModel());
    project.setFile(pom.toFile());
    project.setOriginalModel(result.getRawModel("example:consumer:1"));
    final var snapshot = ExclusionProvenanceCapture.capture(project);
    final var recommendations = ExclusionRecommendations.collect(snapshot);
    final var capture = BanishedDependencyOriginalModel.capture(project, List.of(), List.of());
    final var restored =
        BanishedDependencyCaptureStore.fromPayload(
                BanishedDependencyCaptureStore.empty().withModel(capture).toPayload())
            .find(capture.project());
    assertAll(
        () -> assertThat(restored.exclusionProvenance()).isEqualTo(snapshot),
        () ->
            assertThat(project.getDependencies())
                .extracting(Dependency::getVersion)
                .containsExactly("1", "1"),
        () -> assertThat(recommendations.candidates()).hasSize(1),
        () -> assertThat(recommendations.candidates().getFirst().count()).isEqualTo(2),
        () ->
            assertThat(snapshot.diagnostics())
                .anyMatch(value -> value.contains("Incomplete or ambiguous provenance")),
        () ->
            assertThat(snapshot.dependencies())
                .allSatisfy(
                    declaration -> {
                      final var origin = declaration.exclusions().getFirst().origin();
                      assertAll(
                          () -> assertThat(origin.kind()).isEqualTo("UNKNOWN"),
                          () -> assertThat(origin.modelId()).isEqualTo("example:exclusions-bom:1"),
                          () -> assertThat(origin.source()).contains("bom.xml"),
                          () -> assertThat(origin.line()).isPositive(),
                          () -> assertThat(origin.column()).isPositive(),
                          () -> assertThat(origin.profileId()).isEmpty());
                    }));
  }

  private record BomResolver(Path bom) implements ModelResolver {
    @Override
    public ModelSource resolveModel(final String group, final String artifact, final String version)
        throws UnresolvableModelException {
      if (!"example".equals(group) || !"exclusions-bom".equals(artifact) || !"1".equals(version)) {
        throw new UnresolvableModelException("Unexpected model", group, artifact, version);
      }
      return new FileModelSource(bom.toFile());
    }

    @Override
    public ModelSource resolveModel(final Parent parent) throws UnresolvableModelException {
      return resolveModel(parent.getGroupId(), parent.getArtifactId(), parent.getVersion());
    }

    @Override
    public ModelSource resolveModel(final Dependency dependency) throws UnresolvableModelException {
      return resolveModel(
          dependency.getGroupId(), dependency.getArtifactId(), dependency.getVersion());
    }

    @Override
    public void addRepository(final Repository repository) {
      addRepository(repository, false);
    }

    @Override
    public void addRepository(final Repository repository, final boolean replace) {
      // The fixture resolves only its local BOM.
    }

    @Override
    public ModelResolver newCopy() {
      return this;
    }
  }

  @Test
  void capturesParentProfileAndManagementOriginsFromMavenModelBuilder() throws Exception {
    Files.writeString(
        directory.resolve("pom.xml"),
        """
        <project xmlns="http://maven.apache.org/POM/4.0.0">
          <modelVersion>4.0.0</modelVersion>
          <groupId>example</groupId><artifactId>parent</artifactId><version>1</version><packaging>pom</packaging>
          <dependencyManagement><dependencies><dependency>
            <groupId>libs</groupId><artifactId>managed</artifactId><version>1</version>
            <exclusions><exclusion><groupId>excluded</groupId><artifactId>shared</artifactId></exclusion></exclusions>
          </dependency><dependency>
            <groupId>libs</groupId><artifactId>other</artifactId><version>1</version>
            <exclusions><exclusion><groupId>excluded</groupId><artifactId>other</artifactId></exclusion></exclusions>
          </dependency></dependencies></dependencyManagement>
          <dependencies><dependency><groupId>libs</groupId><artifactId>managed</artifactId></dependency>
            <dependency><groupId>libs</groupId><artifactId>profiled</artifactId><version>1</version></dependency>
          </dependencies>
          <profiles><profile><id>active</id><dependencies><dependency>
            <groupId>libs</groupId><artifactId>profiled</artifactId><version>1</version>
            <exclusions><exclusion><groupId>excluded</groupId><artifactId>shared</artifactId></exclusion></exclusions>
          </dependency></dependencies></profile></profiles>
        </project>
        """);
    final Path child = Files.createDirectory(directory.resolve("child"));
    final Path pom = child.resolve("pom.xml");
    Files.writeString(
        pom,
        """
        <project xmlns="http://maven.apache.org/POM/4.0.0">
          <modelVersion>4.0.0</modelVersion>
          <parent><groupId>example</groupId><artifactId>parent</artifactId><version>1</version></parent>
          <artifactId>child</artifactId>
          <dependencies><dependency><groupId>libs</groupId><artifactId>local</artifactId><version>1</version></dependency></dependencies>
        </project>
        """);
    final var request =
        new DefaultModelBuildingRequest()
            .setPomFile(pom.toFile())
            .setLocationTracking(true)
            .setActiveProfileIds(List.of("active"))
            .setValidationLevel(ModelBuildingRequest.VALIDATION_LEVEL_MINIMAL)
            .setSystemProperties(System.getProperties());
    final var result = new DefaultModelBuilderFactory().newInstance().build(request);
    final MavenProject project = new MavenProject(result.getEffectiveModel());
    project.setFile(pom.toFile());
    project.setOriginalModel(result.getRawModel("example:child:1"));
    final MavenProject parent = new MavenProject(result.getRawModel("example:parent:1"));
    parent.setOriginalModel(result.getRawModel("example:parent:1"));
    project.setParent(parent);
    for (final String id : result.getModelIds()) {
      project.setInjectedProfileIds(
          id, result.getActivePomProfiles(id).stream().map(Profile::getId).toList());
    }
    final var snapshot = ExclusionProvenanceCapture.capture(project);
    final var recommendations = ExclusionRecommendations.collect(snapshot);
    final var capture = BanishedDependencyOriginalModel.capture(project, List.of(), List.of());
    final var restored =
        BanishedDependencyCaptureStore.fromPayload(
                BanishedDependencyCaptureStore.empty().withModel(capture).toPayload())
            .find(capture.project());
    final var managed =
        snapshot.dependencies().stream()
            .filter(row -> "managed".equals(row.reference().artifactId()))
            .findFirst()
            .orElseThrow();
    final var profiled =
        snapshot.dependencies().stream()
            .filter(row -> "profiled".equals(row.reference().artifactId()))
            .findFirst()
            .orElseThrow();
    final var local =
        snapshot.dependencies().stream()
            .filter(row -> "local".equals(row.reference().artifactId()))
            .findFirst()
            .orElseThrow();
    assertAll(
        () -> assertThat(snapshot.diagnostics()).isEmpty(),
        () -> assertThat(restored.exclusionProvenance()).isEqualTo(snapshot),
        () -> assertThat(local.reference().origin().kind()).isEqualTo("LOCAL"),
        () -> assertThat(managed.reference().origin().kind()).isEqualTo("INHERITED"),
        () ->
            assertThat(managed.exclusions().getFirst().origin().kind())
                .isEqualTo("INHERITED_MANAGEMENT"),
        () -> assertThat(profiled.reference().origin().profileId()).isEqualTo("active"),
        () -> assertThat(profiled.exclusions().getFirst().origin().profileId()).isEqualTo("active"),
        () -> assertThat(recommendations.candidates()).hasSize(1),
        () -> assertThat(recommendations.candidates().getFirst().count()).isEqualTo(2),
        () -> assertThat(recommendations.management()).hasSize(1),
        () ->
            assertThat(recommendations.management().getFirst().reference().artifactId())
                .isEqualTo("other"),
        () ->
            assertThat(
                    ExclusionProvenancePayload.decode(ExclusionProvenancePayload.encode(snapshot)))
                .isEqualTo(snapshot));
  }
}
