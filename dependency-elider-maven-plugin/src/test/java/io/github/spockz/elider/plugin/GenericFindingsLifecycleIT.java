/* WHY: Exercises generic vulnerability findings through actual offline Maven goals and output. */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.spockz.elider.model.CacheProducerIdentity;
import io.github.spockz.elider.scanner.CveListFindingIndexer;
import io.github.spockz.elider.scanner.FindingSource;
import io.github.spockz.elider.scanner.FindingSourceSnapshot;
import io.github.spockz.elider.scanner.GenericFindingCacheEnvelope;
import io.github.spockz.elider.scanner.GenericFindingCacheEnvelopeWriter;
import io.github.spockz.elider.scanner.OsvSnapshotIndexer;
import io.github.spockz.elider.scanner.OsvVulnerabilityFindingAdapter;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;
import java.util.stream.Stream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.artifact.DefaultArtifact;
import org.apache.maven.artifact.handler.DefaultArtifactHandler;
import org.apache.maven.plugin.descriptor.PluginDescriptor;
import org.apache.maven.plugin.descriptor.PluginDescriptorBuilder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestReporter;
import org.junit.jupiter.api.function.Executable;
import org.junit.jupiter.api.io.CleanupMode;
import org.junit.jupiter.api.io.TempDir;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

/** Verifies source-independent findings through the packaged plugin goals. */
@SuppressWarnings({
  "PMD.AtLeastOneConstructor",
  "PMD.CouplingBetweenObjects",
  "PMD.ExcessiveImports",
  "PMD.GodClass",
  "PMD.LawOfDemeter",
  "PMD.TooManyMethods",
  "PMD.UnitTestContainsTooManyAsserts"
})
final class GenericFindingsLifecycleIT {
  /** Maven property token replaced in the fixture project and extension. */
  private static final String PLUGIN_VERSION_TOKEN = "@PLUGIN_VERSION@";

  /** Maven property token replaced with manual finding rows in the fixture project. */
  private static final String VULNERABILITY_MAPPINGS_TOKEN = "@VULNERABILITY_MAPPINGS@";

  /** External cache file written by the generic finding cache manager. */
  private static final String CACHE_INDEX = "index.json";

  /** JSON property holding each finding identifier. */
  private static final String VULNERABILITY_ID_FIELD = "vulnerabilityId";

  /** Opening row tag in manual POM mapping fixture data. */
  private static final String MAPPING_OPEN_TAG = "<vulnerabilityMapping>";

  /** Closing row tag in manual POM mapping fixture data. */
  private static final String MAPPING_CLOSE_TAG = "</vulnerabilityMapping>";

  /** Maven group ID shared by manual fixture rows. */
  private static final String MAPPING_GROUP_ID = "io.github.spockz.elider.test";

  /** Maven artifact ID shared by manual fixture rows. */
  private static final String MAPPING_ARTIFACT_ID = "generic-findings-fixture";

  /** Maven version shared by manual fixture rows. */
  private static final String MAPPING_VERSION = "1.0.0";

  /** Group identifier tag used in manual POM rows. */
  private static final String GROUP_ID_TAG = "groupId";

  /** Artifact identifier tag used in manual POM rows. */
  private static final String ARTIFACT_ID_TAG = "artifactId";

  /** Version tag used in manual POM rows. */
  private static final String VERSION_TAG = "version";

  /** Safe class retained in the fixture's trace. */
  private static final String SAFE_CLASS = "org.example.fixture.Safe";

  /** CVE whose cached declaration is enriched with an omitted manual code group. */
  private static final String VULNERABLE_CVE = "CVE-2026-10001";

  /** CVE with an automatic code declaration. */
  private static final String AUTOMATIC_CVE = "CVE-2026-10005";

  /** CVE whose explicit empty manual code group overrides automatic code. */
  private static final String EMPTY_OVERRIDE_CVE = "CVE-2026-10002";

  /** CVE with a manual medium confidence declaration. */
  private static final String MANUAL_REVIEW_CVE = "CVE-2026-10003";

  /** Manual-only CVE retained without external source contributions. */
  private static final String MANUAL_ONLY_CVE = "CVE-2026-10004";

  /** Package-only OSV finding used to verify GHSA identity preservation. */
  private static final String PACKAGE_ONLY_GHSA = "GHSA-2026-10001";

  /** Stable source snapshot timestamp used by the generated cache fixture. */
  private static final Instant SNAPSHOT_TIME = Instant.parse("2026-11-04T00:00:00Z");

  /** Upper bound for each nested Maven process. */
  private static final Duration PROCESS_TIMEOUT = Duration.ofMinutes(3);

  /** JSON parser for the generated report and OpenVEX document. */
  private static final ObjectMapper JSON = new ObjectMapper();

  /** Temporary root for test projects and cache copies. */
  @TempDir(cleanup = CleanupMode.ON_SUCCESS)
  /* package */ Path temporaryDirectory;

  /** Local fixture artifact directory removed after the nested goals complete. */
  private Path fixtureArtifactDirectory;

  @AfterEach
  void removeLocalFixtureArtifact() throws IOException {
    if (fixtureArtifactDirectory != null) {
      try (Stream<Path> paths = Files.walk(fixtureArtifactDirectory)) {
        for (final Path path : paths.sorted(java.util.Comparator.reverseOrder()).toList()) {
          Files.deleteIfExists(path);
        }
      }
    }
  }

  @Test
  void cachedAndManualFindingsSurviveAnalyzeElideAndSavedReportReplay(
      final TestReporter testReporter) throws Exception {
    final Path repositoryRoot = repositoryRoot();
    final Path pluginJar =
        repositoryRoot.resolve(
            "dependency-elider-maven-plugin/target/dependency-elider-maven-plugin-"
                + "0.1.0-SNAPSHOT.jar");
    final Path coreJar =
        repositoryRoot.resolve("elider-core/target/elider-core-0.1.0-SNAPSHOT.jar");
    final Path cachedRepository = Path.of(requiredProperty("maven.repo.local"));
    final Path privateRepository =
        Files.createDirectories(temporaryDirectory.resolve("private-repository"));
    assertThat(privateRepository.toAbsolutePath().normalize())
        .as("private CLI repository must differ from cached dependencies at " + cachedRepository)
        .isNotEqualTo(cachedRepository.toAbsolutePath().normalize());
    testReporter.publishEntry(
        "generic findings repositories",
        "private=" + privateRepository + "; read-only dependency mirror=" + cachedRepository);
    final Path settings =
        MavenFixtureRepositorySettings.write(
            temporaryDirectory, cachedRepository.toUri().toASCIIString());
    installPackagedArtifacts(repositoryRoot, privateRepository, settings);
    final CacheProducerIdentity producer = producerIdentity(pluginJar, coreJar, privateRepository);
    final Path fixture = copyFixture(repositoryRoot, temporaryDirectory.resolve("consumer"));
    final Path cache = Files.createDirectories(temporaryDirectory.resolve("vulnerability-cache"));
    final Path dependencyJar = createDependencyArtifact(privateRepository);
    fixtureArtifactDirectory = dependencyJar.getParent();
    final String initialCacheDigest = sha256(writeGenericCache(producer, repositoryRoot, cache));
    final String mappings = manualMappings();
    final Path pom = fixture.resolve("pom.xml");
    Files.writeString(
        pom,
        Files.readString(pom)
            .replace(PLUGIN_VERSION_TOKEN, producer.version())
            .replace(VULNERABILITY_MAPPINGS_TOKEN, mappings));
    final Path extensions = fixture.resolve(".mvn/extensions.xml");
    Files.writeString(
        extensions, Files.readString(extensions).replace(PLUGIN_VERSION_TOKEN, producer.version()));
    Files.writeString(fixture.resolve("trace.txt"), SAFE_CLASS + "\n");

    assertAll(
        "the real goals retain generic findings, prove only declared code, and replay offline",
        () ->
            assertMixedSourceScenario(
                repositoryRoot,
                fixture,
                privateRepository,
                settings,
                cache,
                producer.version(),
                dependencyJar,
                initialCacheDigest),
        () ->
            assertManualOnlyScenario(
                repositoryRoot,
                temporaryDirectory,
                privateRepository,
                settings,
                producer,
                mappings));
  }

  private static void assertMixedSourceScenario(
      final Path repositoryRoot,
      final Path fixture,
      final Path privateRepository,
      final Path settings,
      final Path cache,
      final String pluginVersion,
      final Path dependencyJar,
      final String initialCacheDigest)
      throws IOException, InterruptedException {
    final String analyzeOutput =
        runGoal(
            repositoryRoot, fixture, privateRepository, settings, cache, pluginVersion, "analyze");
    final Path vexFile = fixture.resolve("target/dependency-elider.openvex.json");
    final boolean analyzeProducedVex = Files.exists(vexFile);
    final String elideOutput =
        runGoal(
            repositoryRoot, fixture, privateRepository, settings, cache, pluginVersion, "elide");
    final Path summary = fixture.resolve("target/dependency-elider-report.json");
    assertThat(summary).isRegularFile();
    final JsonNode savedReport = JSON.readTree(summary.toFile());
    final JsonNode genericFindings = savedReport.path("genericFindings");
    final JsonNode sourceObservations = savedReport.path("sourceObservations");
    final String cacheDigestAfterGoals = sha256(cache.resolve(CACHE_INDEX));

    assertAll(
        "mixed source analyze, elide and saved report replay",
        () -> assertThat(analyzeOutput).contains("BUILD SUCCESS"),
        () -> assertFalse(analyzeProducedVex, "analyze must not publish OpenVEX evidence"),
        () -> assertThat(elideOutput).contains("BUILD SUCCESS"),
        () -> assertThat(cacheDigestAfterGoals).isEqualTo(initialCacheDigest),
        () -> assertTrue(genericFindings.isArray(), "saved report must contain generic findings"),
        () ->
            assertFindingIds(
                genericFindings,
                VULNERABLE_CVE,
                AUTOMATIC_CVE,
                EMPTY_OVERRIDE_CVE,
                MANUAL_REVIEW_CVE,
                MANUAL_ONLY_CVE,
                PACKAGE_ONLY_GHSA),
        () -> assertThat(genericFindings.toString()).doesNotContain("CVE-GHSA-2026-10001"),
        () -> assertSourceObservations(sourceObservations),
        () -> assertOutcome(genericFindings, VULNERABLE_CVE, "DECLARED_CODE_ABSENT"),
        () -> assertOutcome(genericFindings, AUTOMATIC_CVE, "DECLARED_CODE_ABSENT"),
        () -> assertEnrichedField(genericFindings, VULNERABLE_CVE, "code"),
        () -> assertOutcome(genericFindings, MANUAL_REVIEW_CVE, "REVIEW_ONLY"),
        () -> assertCodeGroupStatus(genericFindings, EMPTY_OVERRIDE_CVE, "EXPLICITLY_EMPTY"),
        () -> assertThat(genericFindings.toString()).contains("effective-project-pom"),
        () ->
            assertTrimmedArtifact(
                savedReport,
                fixture.resolve("target/elided-artifacts/.trim-analysis-cache.json"),
                dependencyJar),
        () -> assertOpenVexStatements(vexFile, VULNERABLE_CVE, AUTOMATIC_CVE),
        () ->
            assertSavedReportReplay(
                repositoryRoot, fixture, privateRepository, settings, cache, pluginVersion));
  }

  private static void assertSavedReportReplay(
      final Path repositoryRoot,
      final Path fixture,
      final Path privateRepository,
      final Path settings,
      final Path cache,
      final String pluginVersion)
      throws IOException, InterruptedException {
    Files.writeString(cache.resolve(CACHE_INDEX), "{corrupt cache after report save}");
    final String replayOutput =
        runGoal(
            repositoryRoot, fixture, privateRepository, settings, cache, pluginVersion, "report");
    assertThat(replayOutput).contains(VULNERABLE_CVE, MANUAL_ONLY_CVE);
  }

  private void assertManualOnlyScenario(
      final Path repositoryRoot,
      final Path temporaryDirectory,
      final Path privateRepository,
      final Path settings,
      final CacheProducerIdentity producer,
      final String mappings)
      throws IOException, InterruptedException {
    final Path manualOnlyProject =
        copyFixture(repositoryRoot, temporaryDirectory.resolve("manual-only-consumer"));
    configureProject(manualOnlyProject, producer.version(), mappings);
    final Path emptyCache = Files.createDirectories(temporaryDirectory.resolve("empty-cache"));
    final String emptyCacheDigest = sha256(writeEmptyCache(producer, emptyCache));
    final String manualOnlyOutput =
        runGoal(
            repositoryRoot,
            manualOnlyProject,
            privateRepository,
            settings,
            emptyCache,
            producer.version(),
            "elide");
    final Path manualOnlySummary =
        manualOnlyProject.resolve("target/dependency-elider-report.json");
    assertThat(manualOnlySummary).isRegularFile();
    final JsonNode manualOnlyReport = JSON.readTree(manualOnlySummary.toFile());
    final String manualOnlyCacheDigest = sha256(emptyCache.resolve(CACHE_INDEX));
    final Path manualOnlyVex = manualOnlyProject.resolve("target/dependency-elider.openvex.json");

    assertAll(
        "manual mappings with valid empty source snapshots",
        () -> assertThat(manualOnlyOutput).contains("BUILD SUCCESS"),
        () ->
            assertFindingIds(
                manualOnlyReport.path("genericFindings"),
                VULNERABLE_CVE,
                EMPTY_OVERRIDE_CVE,
                MANUAL_REVIEW_CVE,
                MANUAL_ONLY_CVE),
        () -> assertEmptySourceObservations(manualOnlyReport.path("sourceObservations")),
        () -> assertThat(manualOnlyCacheDigest).isEqualTo(emptyCacheDigest),
        () -> assertThat(manualOnlyVex).doesNotExist());
  }

  private static void configureProject(
      final Path project, final String pluginVersion, final String mappings) throws IOException {
    final Path pom = project.resolve("pom.xml");
    Files.writeString(
        pom,
        Files.readString(pom)
            .replace(PLUGIN_VERSION_TOKEN, pluginVersion)
            .replace(VULNERABILITY_MAPPINGS_TOKEN, mappings));
    final Path extensions = project.resolve(".mvn/extensions.xml");
    Files.writeString(
        extensions, Files.readString(extensions).replace(PLUGIN_VERSION_TOKEN, pluginVersion));
    Files.writeString(project.resolve("trace.txt"), SAFE_CLASS + "\n");
  }

  private static void assertFindingIds(final JsonNode findings, final String... expected) {
    final List<String> identifiers = new ArrayList<>();
    findings.forEach(node -> identifiers.add(node.path(VULNERABILITY_ID_FIELD).asText()));
    assertThat(identifiers).containsExactlyInAnyOrder(expected);
  }

  private static void assertEmptySourceObservations(final JsonNode observations) {
    assertAll(
        () -> assertTrue(observations.isArray(), "empty source observations must be an array"),
        () -> assertThat(observations.size()).isEqualTo(2));
    final List<String> sourceNames = sourceNames(observations);
    final List<Executable> checks = new ArrayList<>();
    checks.add(() -> assertThat(sourceNames).containsExactlyInAnyOrder("CVE_LIST", "OSV"));
    observations.forEach(
        observation ->
            checks.add(
                () -> {
                  assertAll(
                      () -> assertThat(observation.path("status").asText()).isEqualTo("CURRENT"),
                      () -> assertThat(observation.path("contributionCount").asInt()).isZero());
                }));
    assertAll("each empty source snapshot remains current and contributes no findings", checks);
  }

  private static void assertSourceObservations(final JsonNode observations) {
    assertAll(
        () -> assertTrue(observations.isArray(), "source observations must be an array"),
        () -> assertThat(observations.size()).isEqualTo(2));
    final List<String> sourceNames = sourceNames(observations);
    final List<Executable> checks = new ArrayList<>();
    checks.add(() -> assertThat(sourceNames).containsExactlyInAnyOrder("CVE_LIST", "OSV"));
    observations.forEach(
        observation ->
            checks.add(
                () -> {
                  assertAll(
                      () -> assertThat(observation.path("status").asText()).isEqualTo("CURRENT"),
                      () -> assertThat(observation.path("contributionCount").asInt()).isPositive());
                }));
    assertAll("each populated source snapshot is observed as current", checks);
  }

  private static List<String> sourceNames(final JsonNode observations) {
    return observations.findValues("source").stream().map(JsonNode::asText).toList();
  }

  private static void assertOpenVexStatements(final Path vexFile, final String... expectedIds)
      throws IOException {
    assertThat(vexFile).isRegularFile();
    final JsonNode statements = JSON.readTree(vexFile.toFile()).path("statements");
    assertThat(statements.isArray()).isTrue();
    final List<String> ids = new ArrayList<>();
    statements.forEach(statement -> ids.add(statement.path("vulnerability").path("name").asText()));
    assertAll(
        "OpenVEX contains only code-absence statements",
        () -> assertThat(ids).containsExactlyInAnyOrder(expectedIds),
        () -> {
          final List<Executable> checks = new ArrayList<>();
          statements.forEach(
              statement ->
                  checks.add(
                      () ->
                          assertAll(
                              () ->
                                  assertThat(statement.path("status").asText())
                                      .isEqualTo("not_affected"),
                              () ->
                                  assertThat(statement.path("justification").asText())
                                      .isEqualTo("vulnerable_code_not_present"))));
          assertAll("every statement carries the code-absence rationale", checks);
        });
  }

  private static void assertOutcome(
      final JsonNode findings, final String vulnerabilityId, final String expectedOutcome) {
    final JsonNode finding =
        findings.findParents(VULNERABILITY_ID_FIELD).stream()
            .filter(
                node ->
                    node.has("outcome")
                        && vulnerabilityId.equals(node.path(VULNERABILITY_ID_FIELD).asText()))
            .findFirst()
            .orElseThrow(() -> new AssertionError("Missing generic finding " + vulnerabilityId));
    assertThat(finding.path("outcome").asText())
        .as("generic finding outcome for " + vulnerabilityId)
        .isEqualTo(expectedOutcome);
  }

  private static void assertEnrichedField(
      final JsonNode findings, final String vulnerabilityId, final String expectedField) {
    final JsonNode finding =
        findings.findParents(VULNERABILITY_ID_FIELD).stream()
            .filter(
                node ->
                    node.has("enrichedFields")
                        && vulnerabilityId.equals(node.path(VULNERABILITY_ID_FIELD).asText()))
            .findFirst()
            .orElseThrow(() -> new AssertionError("Missing generic finding " + vulnerabilityId));
    final List<String> enrichedFields = new ArrayList<>();
    finding.path("enrichedFields").forEach(value -> enrichedFields.add(value.asText()));
    assertThat(enrichedFields)
        .as("manual omitted fields should be enriched from automatic findings")
        .contains(expectedField);
  }

  private static void assertCodeGroupStatus(
      final JsonNode findings, final String vulnerabilityId, final String expectedStatus) {
    final JsonNode finding =
        findings.findParents(VULNERABILITY_ID_FIELD).stream()
            .filter(
                node ->
                    node.has("codeGroupStatus")
                        && vulnerabilityId.equals(node.path(VULNERABILITY_ID_FIELD).asText()))
            .findFirst()
            .orElseThrow(() -> new AssertionError("Missing generic finding " + vulnerabilityId));
    assertThat(finding.path("codeGroupStatus").asText())
        .as("generic code group status for " + vulnerabilityId)
        .isEqualTo(expectedStatus);
  }

  private static String manualMappings() {
    return String.join(
        "\n",
        List.of(
            MAPPING_OPEN_TAG,
            "  <cveId>CVE-2026-10001</cveId>",
            mappingElement(GROUP_ID_TAG, MAPPING_GROUP_ID),
            mappingElement(ARTIFACT_ID_TAG, MAPPING_ARTIFACT_ID),
            mappingElement(VERSION_TAG, MAPPING_VERSION),
            MAPPING_CLOSE_TAG,
            MAPPING_OPEN_TAG,
            "  <cveId>CVE-2026-10002</cveId>",
            mappingElement(GROUP_ID_TAG, MAPPING_GROUP_ID),
            mappingElement(ARTIFACT_ID_TAG, MAPPING_ARTIFACT_ID),
            mappingElement(VERSION_TAG, MAPPING_VERSION),
            "  <vulnerableClasses/>",
            MAPPING_CLOSE_TAG,
            MAPPING_OPEN_TAG,
            "  <cveId>CVE-2026-10003</cveId>",
            mappingElement(GROUP_ID_TAG, MAPPING_GROUP_ID),
            mappingElement(ARTIFACT_ID_TAG, MAPPING_ARTIFACT_ID),
            mappingElement(VERSION_TAG, MAPPING_VERSION),
            "  <vulnerableClasses>",
            "    <vulnerableClass>org.example.fixture.Vulnerable</vulnerableClass>",
            "  </vulnerableClasses>",
            "  <confidenceLevel>MEDIUM</confidenceLevel>",
            MAPPING_CLOSE_TAG,
            MAPPING_OPEN_TAG,
            "  <cveId>CVE-2026-10004</cveId>",
            mappingElement(GROUP_ID_TAG, MAPPING_GROUP_ID),
            mappingElement(ARTIFACT_ID_TAG, MAPPING_ARTIFACT_ID),
            mappingElement(VERSION_TAG, MAPPING_VERSION),
            MAPPING_CLOSE_TAG,
            ""));
  }

  private static String mappingElement(final String name, final String value) {
    return "  <" + name + ">" + value + "</" + name + ">";
  }

  private Path copyFixture(final Path repositoryRoot, final Path target) throws IOException {
    final Path fixtureRoot =
        repositoryRoot.resolve("dependency-elider-maven-plugin/src/test/fixtures/generic-findings");
    try (Stream<Path> paths = Files.walk(fixtureRoot)) {
      for (final Path source : paths.toList()) {
        final Path destination = target.resolve(fixtureRoot.relativize(source));
        if (Files.isDirectory(source)) {
          Files.createDirectories(destination);
        } else {
          Files.createDirectories(destination.getParent());
          Files.copy(source, destination);
        }
      }
    }
    return target;
  }

  @SuppressWarnings("PMD.UseConcurrentHashMap") // EnumMap stays local to this sequential fixture.
  private static Path writeGenericCache(
      final CacheProducerIdentity producer, final Path repositoryRoot, final Path cache)
      throws IOException {
    final Path cveFixture =
        repositoryRoot.resolve(
            "dependency-elider-maven-plugin/src/test/fixtures/generic-findings/cves");
    final Path checkout = Files.createDirectories(cache.resolve("cve-checkout"));
    copyTree(cveFixture, checkout.resolve("cves"));
    final CveListFindingIndexer.IndexResult cveResult = new CveListFindingIndexer().index(checkout);
    final List<io.github.spockz.elider.model.OsvAdvisoryRecord> osvRecords =
        new OsvSnapshotIndexer().indexZip(osvFixtureZip(repositoryRoot), null);
    final OsvVulnerabilityFindingAdapter osvAdapter = new OsvVulnerabilityFindingAdapter();
    final List<io.github.spockz.elider.model.VulnerabilityFindingContribution> osvContributions =
        osvRecords.stream().flatMap(record -> osvAdapter.contributions(record).stream()).toList();
    final Map<FindingSource, FindingSourceSnapshot> sources = new EnumMap<>(FindingSource.class);
    sources.put(
        FindingSource.OSV,
        new FindingSourceSnapshot(
            FindingSource.OSV,
            "generic-findings-osv-fixture",
            SNAPSHOT_TIME,
            FindingSourceSnapshot.Status.CURRENT,
            null,
            osvContributions,
            List.of()));
    sources.put(
        FindingSource.CVE_LIST,
        new FindingSourceSnapshot(
            FindingSource.CVE_LIST,
            cveResult.revision(),
            SNAPSHOT_TIME,
            FindingSourceSnapshot.Status.CURRENT,
            null,
            cveResult.contributions(),
            cveResult.observationDiagnostics()));
    final byte[] encoded =
        new GenericFindingCacheEnvelopeWriter()
            .encode(new GenericFindingCacheEnvelope(producer, sources));
    final Path index = cache.resolve(CACHE_INDEX);
    Files.write(index, encoded);
    return index;
  }

  @SuppressWarnings("PMD.UseConcurrentHashMap") // EnumMap stays local to this sequential fixture.
  private static Path writeEmptyCache(final CacheProducerIdentity producer, final Path cache)
      throws IOException {
    final Map<FindingSource, FindingSourceSnapshot> sources = new EnumMap<>(FindingSource.class);
    sources.put(
        FindingSource.OSV,
        new FindingSourceSnapshot(
            FindingSource.OSV,
            "empty-osv-fixture",
            SNAPSHOT_TIME,
            FindingSourceSnapshot.Status.CURRENT,
            null,
            List.of(),
            List.of()));
    sources.put(
        FindingSource.CVE_LIST,
        new FindingSourceSnapshot(
            FindingSource.CVE_LIST,
            "empty-cve-fixture",
            SNAPSHOT_TIME,
            FindingSourceSnapshot.Status.CURRENT,
            null,
            List.of(),
            List.of()));
    final Path index = cache.resolve(CACHE_INDEX);
    Files.write(
        index,
        new GenericFindingCacheEnvelopeWriter()
            .encode(new GenericFindingCacheEnvelope(producer, sources)));
    return index;
  }

  private static InputStream osvFixtureZip(final Path repositoryRoot) throws IOException {
    final Path osvFixture =
        repositoryRoot.resolve(
            "dependency-elider-maven-plugin/src/test/fixtures/generic-findings/osv/GHSA-only.json");
    final ByteArrayOutputStream bytes = new ByteArrayOutputStream();
    try (ZipOutputStream zip = new ZipOutputStream(bytes)) {
      zip.putNextEntry(new ZipEntry("GHSA-2026-10001.json"));
      zip.write(Files.readAllBytes(osvFixture));
      zip.closeEntry();
    }
    return new ByteArrayInputStream(bytes.toByteArray());
  }

  private static void copyTree(final Path sourceRoot, final Path targetRoot) throws IOException {
    try (Stream<Path> paths = Files.walk(sourceRoot)) {
      for (final Path source : paths.toList()) {
        final Path destination = targetRoot.resolve(sourceRoot.relativize(source));
        if (Files.isDirectory(source)) {
          Files.createDirectories(destination);
        } else {
          Files.createDirectories(destination.getParent());
          Files.copy(source, destination);
        }
      }
    }
  }

  private static Path createDependencyArtifact(final Path localRepository) throws IOException {
    final Path artifactDirectory =
        localRepository.resolve("io/github/spockz/elider/test/generic-findings-fixture/1.0.0");
    Files.createDirectories(artifactDirectory);
    final Path jar = artifactDirectory.resolve("generic-findings-fixture-1.0.0.jar");
    try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(jar))) {
      writeClass(output, "org/example/fixture/Safe", "Safe.java", "safe");
      writeClass(output, "org/example/fixture/Vulnerable", "Vulnerable.java", "decode");
    }
    Files.writeString(
        artifactDirectory.resolve("generic-findings-fixture-1.0.0.pom"),
        "<project><modelVersion>4.0.0</modelVersion><groupId>io.github.spockz.elider.test</groupId>"
            + "<artifactId>generic-findings-fixture</artifactId><version>1.0.0</version>"
            + "<packaging>jar</packaging></project>");
    return jar;
  }

  private static void writeClass(
      final JarOutputStream output,
      final String internalName,
      final String sourceFile,
      final String method)
      throws IOException {
    final ClassWriter writer = new ClassWriter(0);
    writer.visit(
        Opcodes.V21,
        Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER,
        internalName,
        null,
        "java/lang/Object",
        null);
    writer.visitSource(sourceFile, null);
    final MethodVisitor visitor =
        writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, method, "()V", null, null);
    visitor.visitCode();
    visitor.visitInsn(Opcodes.RETURN);
    visitor.visitMaxs(0, 0);
    visitor.visitEnd();
    writer.visitEnd();
    output.putNextEntry(new JarEntry(internalName + ".class"));
    output.write(writer.toByteArray());
    output.closeEntry();
  }

  @SuppressWarnings("PMD.DoNotUseThreads") // A Maven subprocess exercises the packaged CLI.
  private static String runGoal(
      final Path repositoryRoot,
      final Path project,
      final Path localRepository,
      final Path settings,
      final Path cache,
      final String pluginVersion,
      final String goal)
      throws IOException, InterruptedException {
    final List<String> command =
        new ArrayList<>(
            List.of(
                repositoryRoot.resolve("mvnw").toString(),
                "--batch-mode",
                "--no-transfer-progress",
                "-o",
                "-s",
                settings.toString(),
                "-Dmaven.repo.local=" + localRepository,
                "-Delide.cveCacheDirectory=" + cache,
                "-Delide.osvSnapshotUri=",
                "-Delide.cveListGitUri=",
                "compile",
                "io.github.spockz:dependency-elider-maven-plugin:" + pluginVersion + ":" + goal));
    Files.createDirectories(project.resolve("target"));
    final ProcessBuilder builder =
        new ProcessBuilder(command)
            .directory(project.toFile())
            .redirectErrorStream(true)
            .redirectOutput(project.resolve("target/generic-findings-" + goal + ".log").toFile());
    builder.environment().remove("MAVEN_ARGS");
    builder.environment().put("JAVA_HOME", System.getProperty("java.home"));
    final Process process = builder.start();
    final boolean exited;
    try {
      exited = process.waitFor(PROCESS_TIMEOUT.toMillis(), TimeUnit.MILLISECONDS);
    } catch (final InterruptedException interrupted) {
      process.destroyForcibly();
      Thread.currentThread().interrupt();
      throw interrupted;
    }
    if (!exited) {
      process.destroyForcibly();
      throw new IOException("Maven " + goal + " exceeded " + PROCESS_TIMEOUT);
    }
    final String output =
        Files.readString(project.resolve("target/generic-findings-" + goal + ".log"));
    if (process.exitValue() != 0) {
      throw new IOException("Maven " + goal + " failed:\n" + output);
    }
    return output;
  }

  private static CacheProducerIdentity producerIdentity(
      final Path pluginJar, final Path coreJar, final Path localRepository) throws IOException {
    final PluginDescriptor descriptor;
    try (JarFile jar = new JarFile(pluginJar.toFile())) {
      final JarEntry entry = jar.getJarEntry("META-INF/maven/plugin.xml");
      if (entry == null) {
        throw new IOException("Packaged plugin JAR has no plugin descriptor");
      }
      try (InputStream input = jar.getInputStream(entry);
          InputStreamReader reader = new InputStreamReader(input, StandardCharsets.UTF_8)) {
        descriptor = new PluginDescriptorBuilder().build(reader);
        final Artifact pluginArtifact =
            artifact(descriptor.getGroupId(), descriptor.getArtifactId(), descriptor.getVersion());
        pluginArtifact.setFile(pluginJar.toFile());
        final Artifact coreArtifact =
            artifact(descriptor.getGroupId(), "elider-core", descriptor.getVersion());
        coreArtifact.setFile(coreJar.toFile());
        descriptor.setPluginArtifact(pluginArtifact);
        descriptor.setArtifacts(List.of(coreArtifact));
      } catch (final org.codehaus.plexus.configuration.PlexusConfigurationException exception) {
        throw new IOException("Could not parse packaged plugin descriptor", exception);
      }
    }
    final PluginCacheProducerIdentityResolver.Resolution resolution =
        PluginCacheProducerIdentityResolver.resolve(descriptor);
    final CacheProducerIdentity producer =
        resolution
            .identity()
            .orElseThrow(() -> new IOException("Packaged producer identity is unavailable"));
    final Path pluginInRepository =
        artifactPath(
            localRepository, producer.groupId(), producer.artifactId(), producer.version());
    final Path coreInRepository =
        artifactPath(localRepository, producer.groupId(), "elider-core", producer.version());
    if (Files.mismatch(pluginJar, pluginInRepository) != -1
        || Files.mismatch(coreJar, coreInRepository) != -1) {
      throw new IOException(
          "Maven CLI repository does not contain the exact packaged plugin and core JARs");
    }
    return producer;
  }

  private static Path artifactPath(
      final Path repository, final String groupId, final String artifactId, final String version) {
    return repository
        .resolve(groupId.replace('.', '/'))
        .resolve(artifactId)
        .resolve(version)
        .resolve(artifactId + "-" + version + ".jar");
  }

  @SuppressWarnings("PMD.DoNotUseThreads") // A Maven subprocess installs current packaged bytes.
  private void installPackagedArtifacts(
      final Path repositoryRoot, final Path localRepository, final Path settings)
      throws IOException, InterruptedException {
    final Path log = temporaryDirectory.resolve("install-current-packaged-plugin.log");
    final ProcessBuilder builder =
        new ProcessBuilder(
                repositoryRoot.resolve("mvnw").toString(),
                "--batch-mode",
                "--no-transfer-progress",
                "-s",
                settings.toString(),
                "-Dmaven.repo.local=" + localRepository,
                "-DskipTests",
                "-Djacoco.skip=true",
                "-pl",
                "dependency-elider-maven-plugin",
                "-am",
                "install")
            .directory(repositoryRoot.toFile())
            .redirectErrorStream(true)
            .redirectOutput(log.toFile());
    builder.environment().remove("MAVEN_ARGS");
    builder.environment().put("JAVA_HOME", System.getProperty("java.home"));
    final Process process = builder.start();
    final boolean exited;
    try {
      exited = process.waitFor(PROCESS_TIMEOUT.toMillis(), TimeUnit.MILLISECONDS);
    } catch (final InterruptedException interrupted) {
      process.destroyForcibly();
      Thread.currentThread().interrupt();
      throw interrupted;
    }
    if (!exited) {
      process.destroyForcibly();
      throw new IOException("Current packaged plugin install exceeded " + PROCESS_TIMEOUT);
    }
    if (process.exitValue() != 0) {
      throw new IOException(
          "Could not install exact packaged plugin and core bytes:\n" + Files.readString(log));
    }
  }

  private static Artifact artifact(
      final String groupId, final String artifactId, final String version) {
    return new DefaultArtifact(
        groupId, artifactId, version, "runtime", "jar", null, new DefaultArtifactHandler("jar"));
  }

  private static void assertArchiveContains(
      final Path archive, final String entry, final boolean expected) throws IOException {
    try (JarFile jar = new JarFile(archive.toFile())) {
      assertThat(jar.getEntry(entry) != null).isEqualTo(expected);
    }
  }

  private static void assertTrimmedArtifact(
      final JsonNode savedReport, final Path generationManifest, final Path originalJar)
      throws IOException {
    final String coordinate =
        "io.github.spockz.elider.test:generic-findings-fixture:jar:1.0.0 (compile)";
    final JsonNode trimRecord =
        savedReport.path("trimmedArtifacts").findParents("coordinate").stream()
            .filter(node -> coordinate.equals(node.path("coordinate").asText()))
            .findFirst()
            .orElse(null);
    assertAll(
        "reported trim and original archive evidence",
        () -> assertThat(trimRecord).as("trim record for " + coordinate).isNotNull(),
        () -> {
          if (trimRecord != null) {
            assertThat(trimRecord.path("programClassesPruned").asInt()).isPositive();
          }
        },
        () -> assertArchiveContains(originalJar, "org/example/fixture/Safe.class", true),
        () -> assertArchiveContains(originalJar, "org/example/fixture/Vulnerable.class", true),
        () -> assertTrimmedGeneration(generationManifest, originalJar));
  }

  private static void assertTrimmedGeneration(final Path generationManifest, final Path originalJar)
      throws IOException {
    final String originalPath = originalJar.toAbsolutePath().normalize().toString();
    final JsonNode generation = JSON.readTree(generationManifest.toFile());
    final JsonNode entry =
        generation.path("entries").findParents("originalPath").stream()
            .filter(node -> originalPath.equals(node.path("originalPath").asText()))
            .findFirst()
            .orElseThrow(
                () -> new AssertionError("Missing generation for original JAR " + originalPath));
    final Path trimmedPath = Path.of(entry.path("trimmedPath").asText());
    assertThat(trimmedPath).isRegularFile();
    assertAll(
        "trimmed archive digest and contents",
        () -> assertThat(sha256(trimmedPath)).isEqualTo(entry.path("trimmedSha256").asText()),
        () -> assertArchiveContains(trimmedPath, "org/example/fixture/Safe.class", true),
        () -> assertArchiveContains(trimmedPath, "org/example/fixture/Vulnerable.class", false));
  }

  private static String sha256(final Path path) throws IOException {
    try (InputStream input = Files.newInputStream(path)) {
      final java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
      final byte[] buffer = new byte[8192];
      int count;
      while (true) {
        count = input.read(buffer);
        if (count < 0) {
          break;
        }
        digest.update(buffer, 0, count);
      }
      return java.util.HexFormat.of().formatHex(digest.digest());
    } catch (final java.security.NoSuchAlgorithmException impossible) {
      throw new IOException("SHA-256 unavailable", impossible);
    }
  }

  private static Path repositoryRoot() throws IOException {
    Path directory = Path.of(System.getProperty("user.dir")).toAbsolutePath().normalize();
    while (directory != null && !Files.isRegularFile(directory.resolve("mvnw"))) {
      directory = directory.getParent();
    }
    if (directory == null) {
      throw new IOException("Cannot locate repository root from " + System.getProperty("user.dir"));
    }
    return directory;
  }

  private static String requiredProperty(final String name) throws IOException {
    final String value = System.getProperty(name);
    if (value == null || value.isBlank()) {
      throw new IOException("Required Failsafe property is missing: " + name);
    }
    return value;
  }
}
