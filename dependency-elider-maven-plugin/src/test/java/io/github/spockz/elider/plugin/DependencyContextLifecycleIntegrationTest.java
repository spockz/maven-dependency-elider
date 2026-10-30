/* WHY: Keeps real lifecycle probes outside the published plugin artifact. */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.spockz.elider.scanner.ProductionBytecodeReferenceScanner;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;
import javax.xml.XMLConstants;
import javax.xml.stream.XMLOutputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamWriter;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.CleanupMode;
import org.junit.jupiter.api.io.TempDir;

/** Verifies artifact-view changes across a real Maven lifecycle. */
@SuppressWarnings({
  "PMD.AddEmptyString",
  "PMD.AtLeastOneConstructor",
  "PMD.AvoidInstantiatingObjectsInLoops",
  "PMD.AvoidLiteralsInIfCondition",
  "PMD.CommentDefaultAccessModifier",
  "PMD.CommentRequired",
  "PMD.CouplingBetweenObjects",
  "PMD.CyclomaticComplexity",
  "PMD.ExcessiveImports",
  "PMD.GodClass",
  "PMD.TooManyMethods",
  "PMD.UnitTestContainsTooManyAsserts",
  "PMD.UseConcurrentHashMap"
})
final class DependencyContextLifecycleIntegrationTest {
  private static final String MAVEN_WRAPPER = "mvnw";
  private static final String POM_XML = "pom.xml";
  private static final String CLEAN_GOAL = "clean";
  private static final String MVN_DIRECTORY = ".mvn";
  private static final String EXTENSIONS_XML = "extensions.xml";
  private static final String BUILD_SUCCESS = "BUILD SUCCESS";
  private static final String CONSUMER_ELIDE_POM = "consumer-elide/pom.xml";
  private static final String TRACE_FILE = "trace.txt";
  private static final String KEEP_ENTRY_ROOT = "io.github.spockz.elider.fixture.keep.KeepEntry\n";
  private static final String SEED_PLAN_DISABLED = "-Dlifecycle.seedPlan=false";
  private static final String ELIDER_SUMMARY = "Dependency Elider summary";

  /** Builds immutable fixture artifacts once; failures retain the evidence directory. */
  @TempDir(cleanup = CleanupMode.ON_SUCCESS)
  private static Path seedDirectory;

  private static Path seedRepository;

  /** Isolates fixture builds and retains subprocess evidence when a test fails. */
  @TempDir(cleanup = CleanupMode.ON_SUCCESS)
  private Path temporaryDirectory;

  private static final String NAME_FIELD = "name";
  private static final String GROUP_ID = "io.github.spockz.elider.test";

  private static final String VERSION = "1.0.0";

  private static final String DROP = GROUP_ID + ":drop-library:" + VERSION + ":jar:";

  private static final String KEEP = GROUP_ID + ":keep-library:" + VERSION + ":jar:";

  private static final String DROP_AETHER = GROUP_ID + ":drop-library:jar:" + VERSION;

  private static final String KEEP_AETHER = GROUP_ID + ":keep-library:jar:" + VERSION;

  private static final String TEST_RESOLUTION_SCOPE = "TEST";

  private static final ObjectMapper JSON = new ObjectMapper();

  private static final String TREE_GOAL =
      "org.apache.maven.plugins:maven-dependency-plugin:3.8.1:tree";

  private static final String SHORT_TREE_GOAL = "dependency:tree";

  private static final String TREE_HEADER = "[INFO] --- dependency:3.8.1:tree";

  private static final String DEPENDENCIES_IN = "dependenciesIn=";

  private static final String DEPENDENCIES_OUT = " dependenciesOut=";

  private static final String RESOLVER_EVENT_PREFIX = "RESOLVER_PROBE ";

  private static final String REQUEST_EVENT_PREFIX = "RESOLVER_REQUEST ";

  private static final String LIFECYCLE_REPLACEMENT_FILE_PROPERTY = "-Dlifecycle.replacementFile=";

  private static final Duration PROCESS_TIMEOUT = Duration.ofSeconds(180);

  @BeforeAll
  static void installBootstrapSeed() throws Exception {
    final Path repositoryRoot = repositoryRoot();
    final Path fixtureRoot =
        copyLifecycleFixture(repositoryRoot, seedDirectory.resolve("lifecycle-probe-fixture"));
    final Path evidenceDirectory =
        Files.createDirectories(seedDirectory.resolve("bootstrap-evidence"));
    seedRepository = Files.createDirectories(seedDirectory.resolve("repository"));
    final Path settings = writeSettings(evidenceDirectory);
    final Path wrapper = repositoryRoot.resolve(MAVEN_WRAPPER);
    final String versionOutput =
        run(
            repositoryRoot,
            wrapper,
            settings,
            seedRepository,
            evidenceDirectory.resolve("maven-version.log"),
            PROCESS_TIMEOUT,
            "-version");
    assertThat(versionOutput).contains("Apache Maven 3.9.11");
    run(
        repositoryRoot,
        wrapper,
        settings,
        seedRepository,
        evidenceDirectory.resolve("production-install.log"),
        PROCESS_TIMEOUT,
        "-f",
        repositoryRoot.resolve(POM_XML).toString(),
        "-pl",
        "dependency-elider-maven-plugin",
        "-am",
        "install",
        "-DskipTests");
    run(
        repositoryRoot,
        wrapper,
        settings,
        seedRepository,
        evidenceDirectory.resolve("fixture-bootstrap.log"),
        PROCESS_TIMEOUT,
        "-f",
        fixtureRoot.resolve("bootstrap/pom.xml").toString(),
        CLEAN_GOAL,
        "install");
  }

  @Test
  @SuppressWarnings("PMD.AvoidDuplicateLiterals")
  void lifecycleSnapshotsShowDirectAndResolvedViewsHaveDifferentLaterResolutionBehavior()
      throws Exception {
    final Path repositoryRoot = repositoryRoot();
    final Path fixtureRoot = copyLifecycleFixture(repositoryRoot);
    final Path evidenceDirectory = temporaryDirectory.resolve("lifecycle-probe-evidence");
    Files.createDirectories(evidenceDirectory);
    final Path localRepository = copySeedRepository(evidenceDirectory);
    final Path settings = writeSettings(evidenceDirectory);
    final Path wrapper = repositoryRoot.resolve(MAVEN_WRAPPER);

    final Path dropJar = repositoryArtifact(localRepository, "drop-library");
    final Path keepJar = repositoryArtifact(localRepository, "keep-library");
    final String dropHash = sha256(dropJar);
    final String keepHash = sha256(keepJar);
    final Path replacementJar =
        fixtureRoot.resolve("consumer/target/replacement/keep-library-trimmed.jar");
    writeReplacementJar(replacementJar);
    final String replacementHash = sha256(replacementJar);
    assertThat(replacementHash).isNotEqualTo(keepHash);

    final Path consumerPom = fixtureRoot.resolve("consumer/pom.xml");
    final Path consumerTarget = fixtureRoot.resolve("consumer/target");
    deleteTree(consumerTarget.resolve("lifecycle-probe"));
    final Map<String, PhaseSnapshots> runs = new HashMap<>();
    for (final String mode : List.of("baseline", "resolved-only", "direct-and-resolved")) {
      run(
          repositoryRoot,
          wrapper,
          settings,
          localRepository,
          evidenceDirectory.resolve(mode + ".log"),
          PROCESS_TIMEOUT,
          "-X",
          "-Dorg.slf4j.simpleLogger.showDateTime=true",
          "-Dlifecycle.mode=" + mode,
          LIFECYCLE_REPLACEMENT_FILE_PROPERTY + replacementJar,
          "-f",
          consumerPom.toString(),
          "prepare-package");
      runs.put(mode, phaseSnapshots(consumerTarget.resolve("lifecycle-probe").resolve(mode), mode));
    }

    assertBaseline(runs.get("baseline"), dropJar, dropHash, keepJar, keepHash);
    assertResolvedOnlyControl(
        runs.get("resolved-only"),
        dropJar,
        dropHash,
        keepJar,
        keepHash,
        replacementJar,
        replacementHash);
    assertDirectMutationPersistsAcrossLaterResolution(
        runs.get("direct-and-resolved"),
        dropJar,
        dropHash,
        keepJar,
        keepHash,
        replacementJar,
        replacementHash);

    final Path resolvedOnlySnapshotDirectory =
        consumerTarget.resolve("lifecycle-probe/resolved-only");
    final Map<Path, String> retainedResolvedOnlySnapshots = new HashMap<>();
    for (final String phase : List.of("before", "immediate", "intermediate", "later")) {
      final Path snapshot =
          resolvedOnlySnapshotDirectory.resolve("resolved-only-" + phase + ".tsv");
      retainedResolvedOnlySnapshots.put(snapshot, Files.readString(snapshot));
    }

    run(
        repositoryRoot,
        wrapper,
        settings,
        localRepository,
        evidenceDirectory.resolve("dependency-tree.log"),
        PROCESS_TIMEOUT,
        "-Dlifecycle.mode=resolved-only",
        LIFECYCLE_REPLACEMENT_FILE_PROPERTY + replacementJar,
        "-Dlifecycle.reportDirectory=" + evidenceDirectory.resolve("tree/lifecycle-probe"),
        "-f",
        consumerPom.toString(),
        "initialize",
        TREE_GOAL);
    final String treeOutput = Files.readString(evidenceDirectory.resolve("dependency-tree.log"));
    assertThat(treeOutput).contains(GROUP_ID + ":drop-library:jar:" + VERSION);
    assertThat(treeOutput).contains(GROUP_ID + ":keep-library:jar:" + VERSION);
    for (final Map.Entry<Path, String> snapshot : retainedResolvedOnlySnapshots.entrySet()) {
      assertThat(Files.readString(snapshot.getKey())).isEqualTo(snapshot.getValue());
    }
    assertThat(
            Files.exists(
                evidenceDirectory.resolve("tree/lifecycle-probe/resolved-only-before.tsv")))
        .isTrue();
    assertThat(sha256(dropJar)).isEqualTo(dropHash);
    assertThat(sha256(keepJar)).isEqualTo(keepHash);
  }

  @Test
  void resolverDecoratorChangesEachRepeatedTreeOutput() throws Exception {
    final Path repositoryRoot = repositoryRoot();
    final Path fixtureRoot = copyLifecycleFixture(repositoryRoot);
    final Path evidenceDirectory = temporaryDirectory.resolve("resolver-probe-evidence");
    Files.createDirectories(evidenceDirectory);
    final Path localRepository = copySeedRepository(evidenceDirectory);
    final Path settings = writeSettings(evidenceDirectory);
    final Path wrapper = repositoryRoot.resolve(MAVEN_WRAPPER);
    final Path consumer = fixtureRoot.resolve("consumer");
    final Path consumerPom = consumer.resolve(POM_XML);

    assertResolverExtensionDescriptor(
        repositoryArtifact(localRepository, "resolver-probe-core-extension"));
    assertResolverProbeIsolatedFromHelperJar(
        repositoryArtifact(localRepository, "lifecycle-probe-maven-plugin"));
    final Path dropJar = repositoryArtifact(localRepository, "drop-library");
    final Path keepJar = repositoryArtifact(localRepository, "keep-library");
    final String dropHash = sha256(dropJar);
    final String keepHash = sha256(keepJar);

    final String baselineTree =
        runFromDirectory(
            consumer,
            wrapper,
            settings,
            localRepository,
            evidenceDirectory.resolve("tree-baseline.log"),
            PROCESS_TIMEOUT,
            "-f",
            consumerPom.toString(),
            TREE_GOAL);
    assertTreeRows(baselineTree, 1, 1, 1);
    assertResolverProbe(baselineTree, "mode=baseline", 1, false);
    assertTreeRequestPathsAreDistinct(baselineTree, 1);

    final String transformedTree =
        runFromDirectory(
            consumer,
            wrapper,
            settings,
            localRepository,
            evidenceDirectory.resolve("tree-repeated-active.log"),
            PROCESS_TIMEOUT,
            "-Dresolver.probe.mode=active",
            "-f",
            consumerPom.toString(),
            TREE_GOAL,
            TREE_GOAL);
    assertTreeRows(transformedTree, 2, 0, 1);
    assertResolverProbeFilters(transformedTree, List.of(false, false));
    assertTreeRequestPathsAreDistinct(transformedTree, 2);

    final Path replacementJar = consumer.resolve("target/replacement/keep-library-trimmed.jar");
    writeReplacementJar(replacementJar);
    final String replacementHash = sha256(replacementJar);
    final Path lifecycleSnapshots = evidenceDirectory.resolve("direct-and-resolved-snapshots");
    deleteTree(lifecycleSnapshots);
    final String lifecycleOutput =
        runFromDirectory(
            consumer,
            wrapper,
            settings,
            localRepository,
            evidenceDirectory.resolve("lifecycle-direct-and-resolved.log"),
            PROCESS_TIMEOUT,
            "-Dlifecycle.mode=direct-and-resolved",
            "-Dlifecycle.reportDirectory=" + lifecycleSnapshots,
            LIFECYCLE_REPLACEMENT_FILE_PROPERTY + replacementJar,
            "-Dresolver.probe.mode=active",
            "-f",
            consumerPom.toString(),
            "prepare-package");
    assertLifecycleRequestBypassedDecorator(lifecycleOutput);
    final PhaseSnapshots phases = phaseSnapshots(lifecycleSnapshots, "direct-and-resolved");
    assertDirectMutationPersistsAcrossLaterResolution(
        phases, dropJar, dropHash, keepJar, keepHash, replacementJar, replacementHash);
    assertSessionDecoratorCalls(lifecycleOutput, false);
    assertThat(sha256(dropJar)).isEqualTo(dropHash);
    assertThat(sha256(keepJar)).isEqualTo(keepHash);

    final Path plannedSnapshots = evidenceDirectory.resolve("session-decorator-snapshots");
    final String plannedLifecycleOutput =
        runFromDirectory(
            consumer,
            wrapper,
            settings,
            localRepository,
            evidenceDirectory.resolve("lifecycle-session-decorator.log"),
            PROCESS_TIMEOUT,
            "-Dlifecycle.mode=session-decorator",
            "-Dlifecycle.reportDirectory=" + plannedSnapshots,
            LIFECYCLE_REPLACEMENT_FILE_PROPERTY + replacementJar,
            "-Dresolver.probe.mode=active",
            "-f",
            consumerPom.toString(),
            "prepare-package");
    assertSessionDecoratorCalls(plannedLifecycleOutput, true);
    assertWorkspaceSubstitution(plannedLifecycleOutput, replacementJar);
    final PhaseSnapshots plannedPhases = phaseSnapshots(plannedSnapshots, "session-decorator");
    assertSessionDecoratorArtifactViews(
        plannedPhases, dropJar, dropHash, keepJar, keepHash, replacementJar, replacementHash);
    assertThat(sha256(dropJar)).isEqualTo(dropHash);
    assertThat(sha256(keepJar)).isEqualTo(keepHash);
  }

  @Test
  void packagedProductionExtensionSubstitutesOnlyThePositiveConsumerRetainedJar() throws Exception {
    final Path repositoryRoot = repositoryRoot();
    final Path fixtureRoot = copyLifecycleFixture(repositoryRoot);
    final Path evidenceDirectory = temporaryDirectory.resolve("production-extension-evidence");
    Files.createDirectories(evidenceDirectory);
    final Path localRepository = copySeedRepository(evidenceDirectory);
    final Path settings = writeSettings(evidenceDirectory);
    final Path wrapper = repositoryRoot.resolve(MAVEN_WRAPPER);

    final Path productionJar =
        localRepository.resolve(
            "io/github/spockz/dependency-elider-maven-plugin/0.1.0-SNAPSHOT/"
                + "dependency-elider-maven-plugin-0.1.0-SNAPSHOT.jar");
    assertProductionExtensionPackage(productionJar);

    final Path dropJar = repositoryArtifact(localRepository, "drop-library");
    final Path keepJar = repositoryArtifact(localRepository, "keep-library");
    final String dropHash = sha256(dropJar);
    final String keepHash = sha256(keepJar);
    final Path replacementJar = evidenceDirectory.resolve("replacement/keep-library-trimmed.jar");
    writeReplacementJar(replacementJar);
    final String replacementHash = sha256(replacementJar);

    final Map<String, PhaseSnapshots> consumerRuns = new HashMap<>();
    for (final String mode : List.of("production-positive", "production-negative")) {
      final Path consumer = evidenceDirectory.resolve(mode);
      Files.createDirectories(consumer);
      Files.copy(fixtureRoot.resolve("consumer/pom.xml"), consumer.resolve(POM_XML));
      final boolean extensionEnabled = "production-positive".equals(mode);
      final Path extensionsDirectory = Files.createDirectories(consumer.resolve(MVN_DIRECTORY));
      writeConsumerExtensions(extensionsDirectory.resolve(EXTENSIONS_XML), extensionEnabled);
      final Path snapshots = evidenceDirectory.resolve(mode + "/snapshots");
      final Path modeLog = evidenceDirectory.resolve(mode + ".log");
      final List<String> properties =
          List.of(
              "-Dlifecycle.mode=baseline",
              "-Dlifecycle.reportDirectory=" + snapshots,
              LIFECYCLE_REPLACEMENT_FILE_PROPERTY + replacementJar,
              "-f",
              consumer.resolve(POM_XML).toString());
      runFromDirectory(
          consumer,
          wrapper,
          settings,
          localRepository,
          modeLog,
          PROCESS_TIMEOUT,
          Stream.concat(properties.stream(), Stream.of("prepare-package")).toArray(String[]::new));
      assertThat(Files.readString(modeLog)).contains(BUILD_SUCCESS);
      assertThat(Files.readString(modeLog)).contains("PRODUCTION_PLAN_EVENT_SEEDED");
      consumerRuns.put(mode, phaseSnapshots(snapshots, "baseline"));
    }

    final PhaseSnapshots positive = consumerRuns.get("production-positive");
    assertArtifacts(
        positive.later().direct(), DROP, dropJar, dropHash, KEEP, replacementJar, replacementHash);
    assertArtifacts(
        positive.later().resolved(),
        DROP,
        dropJar,
        dropHash,
        KEEP,
        replacementJar,
        replacementHash);
    final PhaseSnapshots negative = consumerRuns.get("production-negative");
    assertArtifacts(negative.later().direct(), DROP, dropJar, dropHash, KEEP, keepJar, keepHash);
    assertArtifacts(negative.later().resolved(), DROP, dropJar, dropHash, KEEP, keepJar, keepHash);
    assertThat(sha256(dropJar)).isEqualTo(dropHash);
    assertThat(sha256(keepJar)).isEqualTo(keepHash);
  }

  @Test
  @SuppressWarnings("PMD.NcssCount")
  void packagedElideMojoPublishesTrimmedJarForLaterResolution() throws Exception {
    final Path repositoryRoot = repositoryRoot();
    final Path fixtureRoot = copyLifecycleFixture(repositoryRoot);
    final Path evidenceDirectory = temporaryDirectory.resolve("production-mojo-evidence");
    Files.createDirectories(evidenceDirectory);
    final Path localRepository = copySeedRepository(evidenceDirectory);
    final Path settings = writeSettings(evidenceDirectory);
    final Path wrapper = repositoryRoot.resolve(MAVEN_WRAPPER);

    final Path originalDrop = repositoryArtifact(localRepository, "drop-library");
    final Path originalKeep = repositoryArtifact(localRepository, "keep-library");
    final String originalDropHash = sha256(originalDrop);
    final String originalKeepHash = sha256(originalKeep);
    assertThat(originalKeepHash).isNotEqualTo(originalDropHash);

    for (final String mode : List.of("mojo-positive", "mojo-negative")) {
      final Path consumer = evidenceDirectory.resolve(mode);
      Files.createDirectories(consumer);
      Files.copy(fixtureRoot.resolve(CONSUMER_ELIDE_POM), consumer.resolve(POM_XML));
      final Path trace = consumer.resolve(TRACE_FILE);
      Files.writeString(trace, KEEP_ENTRY_ROOT);
      final boolean extensionEnabled = "mojo-positive".equals(mode);
      writeConsumerExtensions(
          Files.createDirectories(consumer.resolve(MVN_DIRECTORY)).resolve(EXTENSIONS_XML),
          extensionEnabled);
      final Path reports = evidenceDirectory.resolve(mode + "/reports");
      final Path log = evidenceDirectory.resolve(mode + ".log");
      runFromDirectory(
          consumer,
          wrapper,
          settings,
          localRepository,
          log,
          PROCESS_TIMEOUT,
          SEED_PLAN_DISABLED,
          "-Dlifecycle.reportDirectory=" + reports,
          "-Dlifecycle.traceFile=" + trace,
          "-f",
          consumer.resolve(POM_XML).toString(),
          "prepare-package");

      final String output = Files.readString(log);
      assertThat(output).contains(BUILD_SUCCESS).doesNotContain("PRODUCTION_PLAN_EVENT_SEEDED");
      final int firstRequest =
          output.indexOf(
              "PRODUCTION_PLAN_EVENT_REQUEST ordinal=1 requestToken=1 planPresent=false");
      final int elideSummary = output.indexOf(ELIDER_SUMMARY);
      final int postPublishRequest =
          output.indexOf(
              "EXPLICIT_TEST_RESOLUTION filter=TEST project=lifecycle-elide-consumer",
              elideSummary);
      assertThat(firstRequest).isGreaterThanOrEqualTo(0);
      assertThat(elideSummary).isGreaterThan(firstRequest);
      assertThat(postPublishRequest).isGreaterThan(elideSummary);
      assertThat(output).doesNotContain("PRODUCTION_PLAN_EVENT_REQUEST ordinal=2");

      final Snapshot initial = Snapshot.read(reports.resolve("initial-later.tsv"));
      final Snapshot postElide = Snapshot.read(reports.resolve("post-elide.tsv"));
      final Snapshot later = Snapshot.read(reports.resolve("later-later.tsv"));
      assertThat(postElide.projectIdentity()).isEqualTo(initial.projectIdentity());
      assertThat(later.projectIdentity()).isEqualTo(initial.projectIdentity());
      assertThat(initial.resolutionScope()).isEqualTo(TEST_RESOLUTION_SCOPE);
      assertThat(postElide.resolutionScope()).isEqualTo(TEST_RESOLUTION_SCOPE);
      assertThat(later.resolutionScope()).isEqualTo(TEST_RESOLUTION_SCOPE);
      assertDirectMembershipUnchanged(postElide, later);
      assertArtifacts(
          initial.direct(),
          DROP,
          originalDrop,
          originalDropHash,
          KEEP,
          originalKeep,
          originalKeepHash);
      assertArtifacts(
          initial.resolved(),
          DROP,
          originalDrop,
          originalDropHash,
          KEEP,
          originalKeep,
          originalKeepHash);
      final ArtifactState postElideKeep = postElide.direct().artifacts().get(KEEP);
      final Path trimmedJar = Path.of(postElideKeep.file());
      final String trimmedHash = postElideKeep.sha256();
      assertThat(Files.isRegularFile(trimmedJar)).isTrue();
      assertThat(trimmedJar).isNotEqualTo(originalKeep);
      assertThat(trimmedHash).isNotEqualTo(originalKeepHash);
      assertJarEntries(trimmedJar);
      assertArtifacts(
          postElide.direct(), DROP, originalDrop, originalDropHash, KEEP, trimmedJar, trimmedHash);
      if (extensionEnabled) {
        assertArtifacts(postElide.resolved(), KEEP, trimmedJar, trimmedHash);
      } else {
        assertArtifacts(
            postElide.resolved(),
            DROP,
            originalDrop,
            originalDropHash,
            KEEP,
            trimmedJar,
            trimmedHash);
      }

      assertArtifacts(
          later.direct(), DROP, originalDrop, originalDropHash, KEEP, trimmedJar, trimmedHash);
      if (extensionEnabled) {
        assertArtifacts(later.resolved(), KEEP, trimmedJar, trimmedHash);
      } else {
        assertArtifacts(
            later.resolved(), DROP, originalDrop, originalDropHash, KEEP, trimmedJar, trimmedHash);
      }
      assertThat(sha256(originalDrop)).isEqualTo(originalDropHash);
      assertThat(sha256(originalKeep)).isEqualTo(originalKeepHash);
      assertMojoOutputReports(consumer, trimmedHash, originalKeepHash, extensionEnabled);
      final Path initialGraph = reports.resolve("graph-initial.tsv");
      final Path laterGraph = reports.resolve("graph-later.tsv");
      final List<String> explicitGraph =
          Files.readAllLines(reports.resolve("graph-explicit-test-resolver.tsv"));
      final List<String> resolvedDependencies =
          Files.readAllLines(reports.resolve("graph-explicit-test-resolved-dependencies.tsv"));
      if (extensionEnabled) {
        assertInitialAndLaterGraphCaptures(initialGraph, laterGraph);
        assertThat(rowsWithPrefix(explicitGraph, "node\t"))
            .containsExactly(
                "node\tn0\tio.github.spockz.elider.test:lifecycle-elide-consumer:1.0.0:pom:",
                "node\tn1\tio.github.spockz.elider.test:keep-library:1.0.0:jar:");
        assertThat(rowsWithPrefix(explicitGraph, "edge\t")).containsExactly("edge\tn0\tn1");
        assertThat(rowsWithPrefix(explicitGraph, "resolved-artifact\t"))
            .containsExactly(resolvedArtifactRow("n1", KEEP, trimmedJar, trimmedHash));
        assertThat(rowsWithPrefix(resolvedDependencies, "resolved-dependency\t"))
            .containsExactly(resolvedDependencyRow(KEEP, trimmedJar, trimmedHash));
      } else {
        assertThat(Files.readString(laterGraph)).contains("missing\ttrue");
        assertThat(rowsWithPrefix(explicitGraph, "node\t"))
            .containsExactly(
                "node\tn0\tio.github.spockz.elider.test:lifecycle-elide-consumer:1.0.0:pom:",
                "node\tn1\tio.github.spockz.elider.test:drop-library:1.0.0:jar:",
                "node\tn2\tio.github.spockz.elider.test:keep-library:1.0.0:jar:");
        assertThat(rowsWithPrefix(explicitGraph, "resolved-artifact\t"))
            .containsExactly(
                resolvedArtifactRow("n1", DROP, originalDrop, originalDropHash),
                resolvedArtifactRow("n2", KEEP, originalKeep, originalKeepHash));
        assertThat(rowsWithPrefix(resolvedDependencies, "resolved-dependency\t"))
            .containsExactly(
                resolvedDependencyRow(DROP, originalDrop, originalDropHash),
                resolvedDependencyRow(KEEP, originalKeep, originalKeepHash));
      }
    }
  }

  @Test
  @DisplayName("ADR-0010/extension rebinds elision after generated bytecode exists")
  void extensionRebindsElideAfterGeneratedBytecodeExists() throws Exception {
    final Path repositoryRoot = repositoryRoot();
    copyLifecycleFixture(repositoryRoot);
    final Path evidenceDirectory = temporaryDirectory.resolve("process-classes-evidence");
    Files.createDirectories(evidenceDirectory);
    final Path localRepository = copySeedRepository(evidenceDirectory);
    final Path settings = writeSettings(evidenceDirectory);
    final Path wrapper = repositoryRoot.resolve(MAVEN_WRAPPER);
    final Path consumer = Files.createDirectories(evidenceDirectory.resolve("consumer"));
    final Path keepJar = repositoryArtifact(localRepository, "keep-library");
    final Path trace = consumer.resolve(TRACE_FILE);
    Files.writeString(trace, KEEP_ENTRY_ROOT);
    writeConsumerExtensions(
        Files.createDirectories(consumer.resolve(MVN_DIRECTORY)).resolve(EXTENSIONS_XML), true);
    final String pom =
        """
        <?xml version="1.0" encoding="UTF-8"?>
        <!-- WHY: Exercises extension rebinding after a generate-sources execution emits real bytecode. -->
        <project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
          <modelVersion>4.0.0</modelVersion><groupId>io.github.spockz.elider.test</groupId><artifactId>process-classes-consumer</artifactId><version>1.0.0</version><packaging>jar</packaging>
          <properties><maven.compiler.release>21</maven.compiler.release><elide.traceFiles>${project.basedir}/trace.txt</elide.traceFiles><elide.summaryFile>${project.build.directory}/dependency-elider-report.json</elide.summaryFile></properties>
          <dependencies>
            <dependency><groupId>io.github.spockz.elider.test</groupId><artifactId>drop-library</artifactId><version>1.0.0</version></dependency>
            <dependency><groupId>io.github.spockz.elider.test</groupId><artifactId>keep-library</artifactId><version>1.0.0</version></dependency>
          </dependencies>
          <build><plugins>
            <plugin><groupId>org.apache.maven.plugins</groupId><artifactId>maven-antrun-plugin</artifactId><version>3.1.0</version><executions><execution><id>generate-bytecode</id><phase>generate-sources</phase><goals><goal>run</goal></goals><configuration><target>
              <mkdir dir="${project.build.directory}/generated-bytecode"/><mkdir dir="${project.build.outputDirectory}"/>
              <echo file="${project.build.directory}/generated-bytecode/GeneratedUse.java">package generated; public final class GeneratedUse { io.github.spockz.elider.fixture.keep.KeepEntry value; }</echo>
              <javac srcdir="${project.build.directory}/generated-bytecode" destdir="${project.build.outputDirectory}" source="21" target="21" includeantruntime="false"><classpath><pathelement location="KEEP_JAR_PATH"/></classpath></javac>
            </target></configuration></execution></executions></plugin>
            <plugin><groupId>org.apache.maven.plugins</groupId><artifactId>maven-compiler-plugin</artifactId><version>3.13.0</version><configuration><release>21</release><proc>none</proc></configuration></plugin>
            <plugin><groupId>io.github.spockz</groupId><artifactId>dependency-elider-maven-plugin</artifactId><version>0.1.0-SNAPSHOT</version><executions><execution><id>run-elider</id><phase>initialize</phase><goals><goal>elide</goal></goals></execution></executions></plugin>
          </plugins></build>
        </project>
        """
            .replace("KEEP_JAR_PATH", keepJar.toString().replace("\\", "\\\\"));
    Files.writeString(consumer.resolve(POM_XML), pom);
    final Path log = evidenceDirectory.resolve("process-classes.log");

    runFromDirectory(
        consumer,
        wrapper,
        settings,
        localRepository,
        log,
        PROCESS_TIMEOUT,
        "-Delide.productionClassesComplete=true",
        "-f",
        consumer.resolve(POM_XML).toString(),
        "dependency:tree");

    final String output = Files.readString(log);
    assertThat(output).contains(BUILD_SUCCESS).contains("Whole artifacts: 1 / 2");
    assertThat(output).contains("dependency-elider:0.1.0-SNAPSHOT:elide (run-elider)");
    final int elideGoal = output.indexOf("elide (run-elider)");
    final int treeGoal = output.indexOf("dependency:3.7.0:tree (default-cli)");
    assertThat(elideGoal).isGreaterThanOrEqualTo(0);
    assertThat(treeGoal).isGreaterThan(elideGoal);
    final Path generatedClass = consumer.resolve("target/classes/generated/GeneratedUse.class");
    assertThat(generatedClass).isRegularFile();
    assertThat(
            new ProductionBytecodeReferenceScanner()
                .scan(consumer.resolve("target/classes"))
                .referencedClasses())
        .contains("io.github.spockz.elider.fixture.keep.KeepEntry");
  }

  @Test
  @SuppressWarnings("PMD.AvoidDuplicateLiterals")
  void packagedElideMojoProjectsSameInvocationDependencyTree() throws Exception {
    final Path repositoryRoot = repositoryRoot();
    final Path fixtureRoot = copyLifecycleFixture(repositoryRoot);
    final Path evidenceDirectory = temporaryDirectory.resolve("production-tree-evidence");
    Files.createDirectories(evidenceDirectory);
    final Path localRepository = copySeedRepository(evidenceDirectory);
    final Path settings = writeSettings(evidenceDirectory);
    final Path wrapper = repositoryRoot.resolve(MAVEN_WRAPPER);

    assertProductionExtensionPackage(
        localRepository.resolve(
            "io/github/spockz/dependency-elider-maven-plugin/0.1.0-SNAPSHOT/"
                + "dependency-elider-maven-plugin-0.1.0-SNAPSHOT.jar"));
    final Path originalDrop = repositoryArtifact(localRepository, "drop-library");
    final Path originalKeep = repositoryArtifact(localRepository, "keep-library");
    final String originalDropHash = sha256(originalDrop);
    final String originalKeepHash = sha256(originalKeep);

    for (final boolean skipElide : List.of(true, false)) {
      final Path consumer = evidenceDirectory.resolve(skipElide ? "tree-skipped" : "tree-elided");
      Files.createDirectories(consumer);
      Files.copy(fixtureRoot.resolve(CONSUMER_ELIDE_POM), consumer.resolve(POM_XML));
      final Path trace = consumer.resolve(TRACE_FILE);
      Files.writeString(trace, KEEP_ENTRY_ROOT);
      writeConsumerExtensions(
          Files.createDirectories(consumer.resolve(MVN_DIRECTORY)).resolve(EXTENSIONS_XML), true);
      final String output =
          runFromDirectory(
              consumer,
              wrapper,
              settings,
              localRepository,
              evidenceDirectory.resolve(skipElide ? "tree-skipped.log" : "tree-elided.log"),
              PROCESS_TIMEOUT,
              "--show-version",
              SEED_PLAN_DISABLED,
              "-Delide.skip=" + skipElide,
              "-Dlifecycle.traceFile=" + trace,
              "-f",
              consumer.resolve(POM_XML).toString(),
              SHORT_TREE_GOAL,
              SHORT_TREE_GOAL);

      assertThat(output)
          .contains("Apache Maven 3.9.11", BUILD_SUCCESS)
          .doesNotContain("PRODUCTION_PLAN_EVENT_SEEDED", RESOLVER_EVENT_PREFIX);
      assertTreeRows(output, 2, skipElide ? 1 : 0, 1);
      assertThat(countOccurrences(output, ELIDER_SUMMARY)).isEqualTo(skipElide ? 0 : 1);
      final Path summary = consumer.resolve("target/lifecycle-elide-summary.json");
      if (skipElide) {
        assertThat(summary).doesNotExist();
      } else {
        final int elideSummary = output.indexOf(ELIDER_SUMMARY);
        assertThat(elideSummary).isGreaterThanOrEqualTo(0);
        assertThat(output.indexOf(TREE_HEADER)).isGreaterThan(elideSummary);
        final JsonNode report = JSON.readTree(summary.toFile());
        assertThat(report.path("wholeArtifactsDropped").asInt()).isOne();
        assertThat(report.path("droppedArtifacts")).hasSize(1);
        assertThat(report.path("droppedArtifacts").get(0).path("coordinate").asText())
            .isEqualTo(DROP_AETHER + " (runtime)");
        assertThat(report.path("trimmedArtifacts")).hasSize(1);
        assertThat(report.path("trimmedArtifacts").get(0).path("coordinate").asText())
            .isEqualTo(KEEP_AETHER + " (runtime)");
        assertThat(report.path("mediatedGraph").path("available").asBoolean()).isTrue();
      }
      assertThat(sha256(originalDrop)).isEqualTo(originalDropHash);
      assertThat(sha256(originalKeep)).isEqualTo(originalKeepHash);
    }
  }

  @Test
  @SuppressWarnings("PMD.AvoidDuplicateLiterals")
  void bareTreeBeforePackageDoesNotRunElideTwice() throws Exception {
    final Path repositoryRoot = repositoryRoot();
    final Path fixtureRoot = copyLifecycleFixture(repositoryRoot);
    final Path evidenceDirectory = temporaryDirectory.resolve("production-tree-package-evidence");
    Files.createDirectories(evidenceDirectory);
    final Path localRepository = copySeedRepository(evidenceDirectory);
    final Path settings = writeSettings(evidenceDirectory);
    final Path wrapper = repositoryRoot.resolve(MAVEN_WRAPPER);
    final Path consumer = evidenceDirectory.resolve("tree-package");
    Files.createDirectories(consumer);
    Files.copy(fixtureRoot.resolve(CONSUMER_ELIDE_POM), consumer.resolve(POM_XML));
    final Path trace = consumer.resolve(TRACE_FILE);
    Files.writeString(trace, KEEP_ENTRY_ROOT);
    writeConsumerExtensions(
        Files.createDirectories(consumer.resolve(MVN_DIRECTORY)).resolve(EXTENSIONS_XML), true);

    final String output =
        runFromDirectory(
            consumer,
            wrapper,
            settings,
            localRepository,
            evidenceDirectory.resolve("tree-package.log"),
            PROCESS_TIMEOUT,
            "--show-version",
            SEED_PLAN_DISABLED,
            "-Delide.skip=false",
            "-Dlifecycle.traceFile=" + trace,
            "-f",
            consumer.resolve(POM_XML).toString(),
            SHORT_TREE_GOAL,
            "package");

    assertThat(output).contains("Apache Maven 3.9.11", BUILD_SUCCESS);
    assertThat(countOccurrences(output, ELIDER_SUMMARY)).isOne();
    assertTreeRows(output, 1, 0, 1);
    final JsonNode report =
        JSON.readTree(consumer.resolve("target/lifecycle-elide-summary.json").toFile());
    assertThat(report.path("wholeArtifactsDropped").asInt()).isOne();
    assertThat(report.path("droppedArtifacts")).hasSize(1);
    assertThat(report.path("mediatedGraph").path("available").asBoolean()).isTrue();
  }

  @Test
  void laterExplicitElideGoalRunsAfterAutomaticTreePreparation() throws Exception {
    final Path repositoryRoot = repositoryRoot();
    final Path fixtureRoot = copyLifecycleFixture(repositoryRoot);
    final Path evidenceDirectory = temporaryDirectory.resolve("tree-explicit-elide-evidence");
    Files.createDirectories(evidenceDirectory);
    final Path localRepository = copySeedRepository(evidenceDirectory);
    final Path settings = writeSettings(evidenceDirectory);
    final Path wrapper = repositoryRoot.resolve(MAVEN_WRAPPER);
    final Path consumer = evidenceDirectory.resolve("tree-explicit-elide");
    Files.createDirectories(consumer);
    final Path pom = consumer.resolve(POM_XML);
    Files.copy(fixtureRoot.resolve(CONSUMER_ELIDE_POM), pom);
    Files.writeString(consumer.resolve(TRACE_FILE), KEEP_ENTRY_ROOT);
    writeConsumerExtensions(
        Files.createDirectories(consumer.resolve(MVN_DIRECTORY)).resolve(EXTENSIONS_XML), true);

    final String output =
        runFromDirectory(
            consumer,
            wrapper,
            settings,
            localRepository,
            evidenceDirectory.resolve("tree-explicit-elide.log"),
            PROCESS_TIMEOUT,
            "--show-version",
            SEED_PLAN_DISABLED,
            "-Delide.skip=false",
            "-f",
            pom.toString(),
            SHORT_TREE_GOAL,
            "io.github.spockz:dependency-elider-maven-plugin:0.1.0-SNAPSHOT:elide@run-elider");

    assertThat(output).contains(BUILD_SUCCESS, TREE_HEADER);
    assertThat(countOccurrences(output, ELIDER_SUMMARY)).isEqualTo(2);
    assertTreeRows(output, 1, 0, 1);
  }

  @Test
  void repeatedLifecyclePhaseAfterTreeRunsAfterSingleDuplicateIsConsumed() throws Exception {
    final Path repositoryRoot = repositoryRoot();
    final Path fixtureRoot = copyLifecycleFixture(repositoryRoot);
    final Path evidenceDirectory = temporaryDirectory.resolve("tree-repeated-phase-evidence");
    Files.createDirectories(evidenceDirectory);
    final Path localRepository = copySeedRepository(evidenceDirectory);
    final Path settings = writeSettings(evidenceDirectory);
    final Path wrapper = repositoryRoot.resolve(MAVEN_WRAPPER);
    final Path consumer = evidenceDirectory.resolve("tree-repeated-phase");
    Files.createDirectories(consumer);
    final Path pom = consumer.resolve(POM_XML);
    Files.copy(fixtureRoot.resolve(CONSUMER_ELIDE_POM), pom);
    Files.writeString(consumer.resolve(TRACE_FILE), KEEP_ENTRY_ROOT);
    writeConsumerExtensions(
        Files.createDirectories(consumer.resolve(MVN_DIRECTORY)).resolve(EXTENSIONS_XML), true);

    final String output =
        runFromDirectory(
            consumer,
            wrapper,
            settings,
            localRepository,
            evidenceDirectory.resolve("tree-repeated-phase.log"),
            PROCESS_TIMEOUT,
            "--show-version",
            SEED_PLAN_DISABLED,
            "-Delide.skip=false",
            "-f",
            pom.toString(),
            SHORT_TREE_GOAL,
            "package",
            "initialize");

    assertThat(output).contains(BUILD_SUCCESS, TREE_HEADER);
    assertThat(countOccurrences(output, ELIDER_SUMMARY)).isEqualTo(2);
    assertTreeRows(output, 1, 0, 1);
  }

  @Test
  void cleanAfterEarlierPackageFailsInsteadOfReusingInvalidatedOutputs() throws Exception {
    final Path repositoryRoot = repositoryRoot();
    final Path fixtureRoot = copyLifecycleFixture(repositoryRoot);
    final Path evidenceDirectory = temporaryDirectory.resolve("package-clean-tree-evidence");
    Files.createDirectories(evidenceDirectory);
    final Path localRepository = copySeedRepository(evidenceDirectory);
    final Path settings = writeSettings(evidenceDirectory);
    final Path wrapper = repositoryRoot.resolve(MAVEN_WRAPPER);
    final Path consumer = evidenceDirectory.resolve("package-clean-tree");
    Files.createDirectories(consumer);
    final Path pom = consumer.resolve(POM_XML);
    Files.copy(fixtureRoot.resolve(CONSUMER_ELIDE_POM), pom);
    Files.writeString(consumer.resolve(TRACE_FILE), KEEP_ENTRY_ROOT);
    writeConsumerExtensions(
        Files.createDirectories(consumer.resolve(MVN_DIRECTORY)).resolve(EXTENSIONS_XML), true);

    final String output =
        runExpectingFailure(
            consumer,
            wrapper,
            settings,
            localRepository,
            evidenceDirectory.resolve("package-clean-tree.log"),
            PROCESS_TIMEOUT,
            "--show-version",
            SEED_PLAN_DISABLED,
            "-Delide.skip=false",
            "-f",
            pom.toString(),
            "package",
            CLEAN_GOAL,
            SHORT_TREE_GOAL);

    assertThat(output)
        .contains(
            "Cannot prepare dependency:tree after clean invalidated earlier lifecycle outputs")
        .doesNotContain(TREE_HEADER);
  }

  @Test
  void cleanAfterEarlierTreeIsRejectedEvenWhenPackagePrecedesTree() throws Exception {
    final Path repositoryRoot = repositoryRoot();
    final Path fixtureRoot = copyLifecycleFixture(repositoryRoot);
    final Path evidenceDirectory =
        temporaryDirectory.resolve("package-tree-clean-package-evidence");
    Files.createDirectories(evidenceDirectory);
    final Path localRepository = copySeedRepository(evidenceDirectory);
    final Path settings = writeSettings(evidenceDirectory);
    final Path wrapper = repositoryRoot.resolve(MAVEN_WRAPPER);
    final Path consumer = evidenceDirectory.resolve("package-tree-clean-package");
    Files.createDirectories(consumer);
    final Path pom = consumer.resolve(POM_XML);
    Files.copy(fixtureRoot.resolve(CONSUMER_ELIDE_POM), pom);
    writeConsumerExtensions(
        Files.createDirectories(consumer.resolve(MVN_DIRECTORY)).resolve(EXTENSIONS_XML), true);

    final String output =
        runExpectingFailure(
            consumer,
            wrapper,
            settings,
            localRepository,
            evidenceDirectory.resolve("package-tree-clean-package.log"),
            PROCESS_TIMEOUT,
            "--show-version",
            SEED_PLAN_DISABLED,
            "-Delide.skip=false",
            "-f",
            pom.toString(),
            "package",
            SHORT_TREE_GOAL,
            CLEAN_GOAL,
            "package");

    assertThat(output)
        .contains("Cannot combine automatic dependency:tree preparation with a later clean goal");
  }

  @Test
  void treeAutoPreparationRejectsAnyMultiProjectReactor() throws Exception {
    final Path repositoryRoot = repositoryRoot();
    final Path fixtureRoot = copyLifecycleFixture(repositoryRoot);
    final Path evidenceDirectory = temporaryDirectory.resolve("multi-project-tree-evidence");
    Files.createDirectories(evidenceDirectory);
    final Path localRepository = copySeedRepository(evidenceDirectory);
    final Path settings = writeSettings(evidenceDirectory);
    final Path wrapper = repositoryRoot.resolve(MAVEN_WRAPPER);
    final Path reactor = evidenceDirectory.resolve("multi-project");
    final Path consumer = reactor.resolve("consumer");
    Files.createDirectories(consumer);
    Files.writeString(
        reactor.resolve(POM_XML),
        "<project xmlns=\"http://maven.apache.org/POM/4.0.0\">"
            + "<modelVersion>4.0.0</modelVersion><groupId>fixture</groupId>"
            + "<artifactId>reactor</artifactId><version>1</version><packaging>pom</packaging>"
            + "<modules><module>consumer</module></modules></project>");
    Files.copy(fixtureRoot.resolve(CONSUMER_ELIDE_POM), consumer.resolve(POM_XML));
    writeConsumerExtensions(
        Files.createDirectories(reactor.resolve(MVN_DIRECTORY)).resolve(EXTENSIONS_XML), true);

    final String output =
        runExpectingFailure(
            reactor,
            wrapper,
            settings,
            localRepository,
            evidenceDirectory.resolve("multi-project-tree.log"),
            PROCESS_TIMEOUT,
            "-T2",
            "--show-version",
            SEED_PLAN_DISABLED,
            "-Delide.skip=false",
            "-f",
            reactor.resolve(POM_XML).toString(),
            SHORT_TREE_GOAL);

    assertThat(output)
        .contains(
            "Automatic dependency:tree preparation does not support multi-project Maven reactors")
        .doesNotContain(TREE_HEADER);
  }

  @Test
  void alreadyPreparedTreeRequestDoesNotAddAnotherElideExecution() throws Exception {
    final Path repositoryRoot = repositoryRoot();
    final Path fixtureRoot = copyLifecycleFixture(repositoryRoot);
    final Path evidenceDirectory = temporaryDirectory.resolve("prepared-tree-evidence");
    Files.createDirectories(evidenceDirectory);
    final Path localRepository = copySeedRepository(evidenceDirectory);
    final Path settings = writeSettings(evidenceDirectory);
    final Path wrapper = repositoryRoot.resolve(MAVEN_WRAPPER);
    final Path consumer = evidenceDirectory.resolve("prepared-tree");
    Files.createDirectories(consumer);
    final Path pom = consumer.resolve(POM_XML);
    Files.copy(fixtureRoot.resolve(CONSUMER_ELIDE_POM), pom);
    Files.writeString(consumer.resolve(TRACE_FILE), KEEP_ENTRY_ROOT);
    writeConsumerExtensions(
        Files.createDirectories(consumer.resolve(MVN_DIRECTORY)).resolve(EXTENSIONS_XML), true);

    final String output =
        runFromDirectory(
            consumer,
            wrapper,
            settings,
            localRepository,
            evidenceDirectory.resolve("prepared-tree.log"),
            PROCESS_TIMEOUT,
            "--show-version",
            SEED_PLAN_DISABLED,
            "-Delide.skip=false",
            "-f",
            pom.toString(),
            "initialize",
            SHORT_TREE_GOAL);

    assertThat(output).contains(BUILD_SUCCESS);
    assertThat(countOccurrences(output, ELIDER_SUMMARY)).isOne();
    assertTreeRows(output, 1, 0, 1);
  }

  @Test
  void ordinaryTestLifecycleDoesNotTriggerTreePreparation() throws Exception {
    final Path repositoryRoot = repositoryRoot();
    final Path fixtureRoot = copyLifecycleFixture(repositoryRoot);
    final Path evidenceDirectory = temporaryDirectory.resolve("ordinary-test-evidence");
    Files.createDirectories(evidenceDirectory);
    final Path localRepository = copySeedRepository(evidenceDirectory);
    final Path settings = writeSettings(evidenceDirectory);
    final Path wrapper = repositoryRoot.resolve(MAVEN_WRAPPER);
    final Path consumer = evidenceDirectory.resolve("ordinary-test");
    Files.createDirectories(consumer);
    final Path pom = consumer.resolve(POM_XML);
    Files.copy(fixtureRoot.resolve(CONSUMER_ELIDE_POM), pom);
    Files.writeString(consumer.resolve(TRACE_FILE), KEEP_ENTRY_ROOT);
    writeConsumerExtensions(
        Files.createDirectories(consumer.resolve(MVN_DIRECTORY)).resolve(EXTENSIONS_XML), true);

    final String output =
        runFromDirectory(
            consumer,
            wrapper,
            settings,
            localRepository,
            evidenceDirectory.resolve("ordinary-test.log"),
            PROCESS_TIMEOUT,
            "--show-version",
            SEED_PLAN_DISABLED,
            "-Delide.skip=false",
            "-f",
            pom.toString(),
            "test");

    assertThat(output).contains(BUILD_SUCCESS).doesNotContain(":tree");
    assertThat(countOccurrences(output, ELIDER_SUMMARY)).isOne();
  }

  @Test
  void explicitPomSkipWinsOverUserPropertyForAutoPreparedTree() throws Exception {
    final Path repositoryRoot = repositoryRoot();
    final Path fixtureRoot = copyLifecycleFixture(repositoryRoot);
    final Path evidenceDirectory = temporaryDirectory.resolve("pom-skip-tree-evidence");
    Files.createDirectories(evidenceDirectory);
    final Path localRepository = copySeedRepository(evidenceDirectory);
    final Path settings = writeSettings(evidenceDirectory);
    final Path wrapper = repositoryRoot.resolve(MAVEN_WRAPPER);
    final Path consumer = evidenceDirectory.resolve("pom-skip-tree");
    Files.createDirectories(consumer);
    final Path pom = consumer.resolve(POM_XML);
    final String pomContents =
        Files.readString(fixtureRoot.resolve(CONSUMER_ELIDE_POM))
            .replace("<trimJars>true</trimJars>", "<skip>true</skip><trimJars>true</trimJars>");
    Files.writeString(pom, pomContents);
    writeConsumerExtensions(
        Files.createDirectories(consumer.resolve(MVN_DIRECTORY)).resolve(EXTENSIONS_XML), true);

    final String output =
        runFromDirectory(
            consumer,
            wrapper,
            settings,
            localRepository,
            evidenceDirectory.resolve("pom-skip-tree.log"),
            PROCESS_TIMEOUT,
            "--show-version",
            SEED_PLAN_DISABLED,
            "-Delide.skip=false",
            "-f",
            pom.toString(),
            SHORT_TREE_GOAL);

    assertThat(output).contains(BUILD_SUCCESS, TREE_HEADER).doesNotContain(ELIDER_SUMMARY);
    assertThat(consumer.resolve("target/lifecycle-elide-summary.json")).doesNotExist();
  }

  @Test
  void cleanAfterTreeBeforePackageFailsBeforeGoalRewrite() throws Exception {
    final Path repositoryRoot = repositoryRoot();
    final Path fixtureRoot = copyLifecycleFixture(repositoryRoot);
    final Path evidenceDirectory = temporaryDirectory.resolve("tree-clean-package-evidence");
    Files.createDirectories(evidenceDirectory);
    final Path localRepository = copySeedRepository(evidenceDirectory);
    final Path settings = writeSettings(evidenceDirectory);
    final Path wrapper = repositoryRoot.resolve(MAVEN_WRAPPER);
    final Path consumer = evidenceDirectory.resolve("tree-clean-package");
    Files.createDirectories(consumer);
    final Path pom = consumer.resolve(POM_XML);
    Files.copy(fixtureRoot.resolve(CONSUMER_ELIDE_POM), pom);
    writeConsumerExtensions(
        Files.createDirectories(consumer.resolve(MVN_DIRECTORY)).resolve(EXTENSIONS_XML), true);

    final String output =
        runExpectingFailure(
            consumer,
            wrapper,
            settings,
            localRepository,
            evidenceDirectory.resolve("tree-clean-package.log"),
            PROCESS_TIMEOUT,
            "--show-version",
            SEED_PLAN_DISABLED,
            "-Delide.skip=false",
            "-f",
            pom.toString(),
            SHORT_TREE_GOAL,
            CLEAN_GOAL,
            "package");

    assertThat(output)
        .contains("Cannot combine automatic dependency:tree preparation with a later clean goal");
  }

  @SuppressWarnings("PMD.AvoidDuplicateLiterals")
  private static void writeConsumerExtensions(
      final Path descriptor, final boolean includeProduction)
      throws IOException, XMLStreamException {
    try (OutputStream output = Files.newOutputStream(descriptor)) {
      final XMLStreamWriter xml =
          XMLOutputFactory.newFactory().createXMLStreamWriter(output, "UTF-8");
      try {
        xml.writeStartDocument("UTF-8", "1.0");
        xml.writeStartElement("extensions");
        writeExtension(
            xml, "io.github.spockz.elider.test", "production-plan-seed-extension", "1.0.0");
        if (includeProduction) {
          writeExtension(
              xml, "io.github.spockz", "dependency-elider-maven-plugin", "0.1.0-SNAPSHOT");
        }
        xml.writeEndElement();
        xml.writeEndDocument();
      } finally {
        xml.close();
      }
    }
  }

  private static void writeExtension(
      final XMLStreamWriter xml,
      final String groupId,
      final String artifactId,
      final String version)
      throws XMLStreamException {
    xml.writeStartElement("extension");
    writeTextElement(xml, "groupId", groupId);
    writeTextElement(xml, "artifactId", artifactId);
    writeTextElement(xml, "version", version);
    xml.writeEndElement();
  }

  private static void assertProductionExtensionPackage(final Path productionJar)
      throws IOException {
    assertThat(productionJar).isRegularFile();
    try (JarFile jar = new JarFile(productionJar.toFile())) {
      final JarEntry index = jar.getJarEntry("META-INF/sisu/javax.inject.Named");
      assertThat(index).isNotNull();
      try (InputStream input = jar.getInputStream(index)) {
        assertThat(new String(input.readAllBytes(), StandardCharsets.UTF_8))
            .contains("io.github.spockz.elider.plugin.EliderRepositorySessionDecorator")
            .contains("io.github.spockz.elider.plugin.EliderMediatedGraphCaptureDecorator")
            .contains("io.github.spockz.elider.plugin.EliderLifecycleParticipant");
      }
      assertThat(
              jar.getJarEntry(
                  "io/github/spockz/elider/plugin/EliderRepositorySessionDecorator.class"))
          .isNotNull();
      assertThat(
              jar.getJarEntry(
                  "io/github/spockz/elider/plugin/EliderMediatedGraphCaptureDecorator.class"))
          .isNotNull();
      assertThat(jar.getJarEntry("io/github/spockz/elider/plugin/EliderLifecycleParticipant.class"))
          .isNotNull();
      assertThat(
              jar.getJarEntry("io/github/spockz/elider/test/resolver/ResolverSessionProbe.class"))
          .isNull();
      assertThat(jar.getJarEntry("io/github/spockz/elider/test/MutateArtifactViewsMojo.class"))
          .isNull();
      assertThat(
              jar.getJarEntry("io/github/spockz/elider/test/resolver/seed/PlanSeedEventSpy.class"))
          .isNull();
    }
  }

  private static void assertInitialAndLaterGraphCaptures(
      final Path initialFile, final Path laterFile) throws IOException {
    final List<String> initialLines = Files.readAllLines(initialFile);
    final List<String> laterLines = Files.readAllLines(laterFile);
    final List<String> initialCaptures = rowsWithPrefix(initialLines, "snapshot\t");
    final List<String> laterCaptures = rowsWithPrefix(laterLines, "snapshot\t");
    assertThat(initialCaptures).hasSize(1);
    assertThat(laterCaptures).hasSize(2).contains(initialCaptures.getFirst());

    final String[] initialFields = initialCaptures.getFirst().split("\\t", -1);
    assertThat(initialFields[2]).isEqualTo("false");
    assertThat(initialFields[3]).isEqualTo("<absent>");
    final List<String> initialNodes = rowsWithPrefix(initialLines, "node\t0\t");
    assertThat(initialNodes)
        .containsExactly(
            "node\t0\tn0\tio.github.spockz.elider.test:lifecycle-elide-consumer:1.0.0:pom:",
            "node\t0\tn1\tio.github.spockz.elider.test:drop-library:1.0.0:jar:",
            "node\t0\tn2\tio.github.spockz.elider.test:keep-library:1.0.0:jar:");
    assertThat(rowsWithPrefix(initialLines, "edge\t0\t"))
        .containsExactly("edge\t0\tn0\tn1", "edge\t0\tn0\tn2");

    final List<String[]> laterWithPlan =
        laterCaptures.stream()
            .map(line -> line.split("\\t", -1))
            .filter(fields -> "true".equals(fields[2]))
            .toList();
    assertThat(laterWithPlan).hasSize(1);
    assertThat(laterWithPlan.getFirst()[3]).matches("[0-9a-f]{64}");
    assertThat(laterWithPlan.getFirst()[4]).isEqualTo("1");
    assertThat(laterWithPlan.getFirst()[5]).isEqualTo("2");
    assertThat(Long.parseLong(laterWithPlan.getFirst()[4]))
        .isGreaterThan(Long.parseLong(initialFields[4]));
    assertThat(rowsWithPrefix(laterLines, "node\t1\t"))
        .containsExactly(
            "node\t1\tn0\tio.github.spockz.elider.test:lifecycle-elide-consumer:1.0.0:pom:",
            "node\t1\tn1\tio.github.spockz.elider.test:keep-library:1.0.0:jar:");
    assertThat(rowsWithPrefix(laterLines, "edge\t1\t")).containsExactly("edge\t1\tn0\tn1");
  }

  private static List<String> rowsWithPrefix(final List<String> lines, final String prefix) {
    return lines.stream().filter(line -> line.startsWith(prefix)).toList();
  }

  private static String resolvedArtifactRow(
      final String nodeId, final String coordinate, final Path path, final String digest) {
    final String encodedPath =
        Base64.getUrlEncoder()
            .withoutPadding()
            .encodeToString(
                path.toAbsolutePath().normalize().toString().getBytes(StandardCharsets.UTF_8));
    return "resolved-artifact\t" + nodeId + "\t" + coordinate + "\t" + encodedPath + "\t" + digest;
  }

  private static String resolvedDependencyRow(
      final String coordinate, final Path path, final String digest) {
    final String encodedPath =
        Base64.getUrlEncoder()
            .withoutPadding()
            .encodeToString(
                path.toAbsolutePath().normalize().toString().getBytes(StandardCharsets.UTF_8));
    return "resolved-dependency\t" + coordinate + "\t" + encodedPath + "\t" + digest;
  }

  private static void assertJarEntries(final Path trimmedJar) throws IOException {
    try (JarFile jar = new JarFile(trimmedJar.toFile())) {
      assertThat(jar.getJarEntry("io/github/spockz/elider/fixture/keep/KeepEntry.class"))
          .isNotNull();
      assertThat(jar.getJarEntry("io/github/spockz/elider/fixture/keep/UnusedEntry.class"))
          .isNull();
    }
  }

  private static void assertMojoOutputReports(
      final Path consumer,
      final String trimmedHash,
      final String originalKeepHash,
      final boolean extensionEnabled)
      throws IOException {
    final Path target = consumer.resolve("target");
    final Path classUsageReport = target.resolve("dependency-elider-class-usage.json");
    final Path summary = target.resolve("lifecycle-elide-summary.json");
    final Path sbom = target.resolve("dependency-elider-sbom.cdx.json");
    assertThat(classUsageReport).isRegularFile();
    final JsonNode report = JSON.readTree(summary.toFile());
    assertThat(report.path("projectGroupId").asText()).isEqualTo(GROUP_ID);
    assertThat(report.path("projectArtifactId").asText()).isEqualTo("lifecycle-elide-consumer");
    assertThat(report.path("projectVersion").asText()).isEqualTo(VERSION);
    assertThat(report.path("projectBaseDirectory").asText())
        .isEqualTo(consumer.toAbsolutePath().normalize().toString());
    assertThat(report.path("wholeArtifactsDropped").asInt()).isEqualTo(extensionEnabled ? 1 : 0);
    assertThat(report.path("rawDroppedCoordinates")).hasSize(1);
    assertThat(report.path("programClassesPruned").asInt()).isEqualTo(1);
    final int classesInDroppedArtifacts = report.path("droppedProgramClassEntries").asInt();
    final long droppedArtifactClassBytes = report.path("droppedProgramClassBytes").asLong();
    assertThat(classesInDroppedArtifacts).isEqualTo(extensionEnabled ? 1 : 0);
    if (extensionEnabled) {
      assertThat(droppedArtifactClassBytes).isPositive();
    } else {
      assertThat(droppedArtifactClassBytes).isZero();
    }
    assertThat(report.path("droppedArtifacts")).hasSize(extensionEnabled ? 1 : 0);
    if (extensionEnabled) {
      final JsonNode droppedArtifact = report.path("droppedArtifacts").get(0);
      assertThat(droppedArtifact.path("coordinate").asText()).contains("drop-library");
      assertThat(droppedArtifact.path("programClassesRemoved").asInt()).isEqualTo(1);
      assertThat(droppedArtifact.path("uncompressedProgramClassBytesRemoved").asLong())
          .isEqualTo(droppedArtifactClassBytes)
          .isPositive();
    }
    assertThat(report.path("trimmedArtifacts")).hasSize(1);
    assertThat(report.path("trimmedArtifacts").get(0).path("coordinate").asText())
        .contains("keep-library");
    assertThat(report.path("trimmedArtifacts").get(0).path("programClassesPruned").asInt())
        .isEqualTo(1);

    final JsonNode bom = JSON.readTree(sbom.toFile());
    assertThat(bom.path("metadata").path("component").path(NAME_FIELD).asText())
        .isEqualTo("lifecycle-elide-consumer");
    assertThat(bom.path("components")).hasSize(extensionEnabled ? 1 : 2);
    final JsonNode component =
        StreamSupport.stream(bom.path("components").spliterator(), false)
            .filter(item -> "keep-library".equals(item.path(NAME_FIELD).asText()))
            .findFirst()
            .orElseThrow();
    assertThat(component.path("group").asText()).isEqualTo(GROUP_ID);
    assertThat(component.path(NAME_FIELD).asText()).isEqualTo("keep-library");
    assertThat(component.path("version").asText()).isEqualTo(VERSION);
    assertThat(component.path("hashes").get(0).path("content").asText()).isEqualTo(trimmedHash);
    assertThat(
            component
                .path("pedigree")
                .path("ancestors")
                .get(0)
                .path("hashes")
                .get(0)
                .path("content")
                .asText())
        .isEqualTo(originalKeepHash);
    assertThat(componentProperty(component, "elider:retainedClasses")).isEqualTo("1");
    assertThat(componentProperty(component, "elider:totalClasses")).isEqualTo("2");
  }

  private static String componentProperty(final JsonNode component, final String propertyName) {
    for (final JsonNode property : component.path("properties")) {
      if (propertyName.equals(property.path(NAME_FIELD).asText())) {
        return property.path("value").asText();
      }
    }
    throw new AssertionError("Missing SBOM property: " + propertyName);
  }

  private static void assertResolverExtensionDescriptor(final Path extensionJar)
      throws IOException {
    try (JarFile jar = new JarFile(extensionJar.toFile())) {
      final JarEntry descriptor = jar.getJarEntry("META-INF/plexus/components.xml");
      assertThat(descriptor).isNotNull();
      try (InputStream input = jar.getInputStream(descriptor)) {
        final String contents = new String(input.readAllBytes(), StandardCharsets.UTF_8);
        assertThat(contents)
            .contains("<role-hint>resolver-probe-delegate</role-hint>")
            .contains("org.apache.maven.project.DefaultProjectDependenciesResolver");
      }
      final JarEntry componentIndex = jar.getJarEntry("META-INF/sisu/javax.inject.Named");
      assertThat(componentIndex).isNotNull();
      try (InputStream input = jar.getInputStream(componentIndex)) {
        assertThat(new String(input.readAllBytes(), StandardCharsets.UTF_8))
            .contains("io.github.spockz.elider.test.resolver.ResolverGraphProbe")
            .contains("io.github.spockz.elider.test.resolver.ResolverRequestEventSpy")
            .contains("io.github.spockz.elider.test.resolver.ResolverSessionProbe");
      }
    }
  }

  private static void assertResolverProbeIsolatedFromHelperJar(final Path helperJar)
      throws IOException {
    try (JarFile jar = new JarFile(helperJar.toFile())) {
      assertThat(jar.getJarEntry("io/github/spockz/elider/test/resolver/ResolverGraphProbe.class"))
          .isNull();
      assertThat(
              jar.getJarEntry(
                  "io/github/spockz/elider/test/resolver/ResolverRequestEventSpy.class"))
          .isNull();
      assertThat(
              jar.getJarEntry("io/github/spockz/elider/test/resolver/ResolverSessionProbe.class"))
          .isNull();
      assertThat(jar.getJarEntry("io/github/spockz/elider/test/MutateArtifactViewsMojo.class"))
          .isNotNull();
    }
  }

  private static void assertTreeRows(
      final String output,
      final int expectedTreeRuns,
      final long expectedDropRows,
      final long expectedKeepRows) {
    final List<String> treeRuns =
        List.of(output.split("(?=\\[INFO\\] --- dependency:3\\.8\\.1:tree)")).stream()
            .filter(run -> run.contains(TREE_HEADER))
            .toList();
    assertThat(treeRuns).hasSize(expectedTreeRuns);
    for (final String treeRun : treeRuns) {
      final List<String> rows =
          treeRun
              .lines()
              .filter(
                  line ->
                      line.contains("[INFO]") && (line.contains("+- ") || line.contains("\\- ")))
              .toList();
      assertThat(rows.stream().filter(line -> line.contains("drop-library")).count())
          .isEqualTo(expectedDropRows);
      assertThat(rows.stream().filter(line -> line.contains("keep-library")).count())
          .isEqualTo(expectedKeepRows);
    }
  }

  private static int countOccurrences(final String value, final String token) {
    int count = 0;
    int next = 0;
    while (true) {
      next = value.indexOf(token, next);
      if (next < 0) {
        return count;
      }
      count++;
      next += token.length();
    }
  }

  private static void assertTreeRequestPathsAreDistinct(
      final String output, final int expectedCalls) {
    final List<String> requestEvents =
        output.lines().filter(line -> line.startsWith(REQUEST_EVENT_PREFIX)).toList();
    final List<String> resolverEvents =
        output.lines().filter(line -> line.startsWith(RESOLVER_EVENT_PREFIX)).toList();
    assertThat(requestEvents).isNotEmpty();
    assertThat(resolverEvents).hasSize(expectedCalls);
    for (final String request : requestEvents) {
      assertThat(request).contains("filter=[drop-library=false, keep-library=false]");
      assertThat(resolverEvents)
          .as("the lifecycle request is a separate resolver path from dependency:tree")
          .noneMatch(event -> requestToken(event).equals(requestToken(request)));
    }
    for (final String resolverEvent : resolverEvents) {
      assertThat(resolverEvent)
          .contains("io.github.spockz.elider.test:drop-library:jar:1.0.0=false")
          .contains("io.github.spockz.elider.test:keep-library:jar:1.0.0=false");
    }
  }

  private static void assertLifecycleRequestBypassedDecorator(final String output) {
    final List<String> lifecycleRequests =
        output
            .lines()
            .filter(line -> line.startsWith(REQUEST_EVENT_PREFIX))
            .filter(line -> line.contains("keep-library=true"))
            .toList();
    final List<String> resolverEvents =
        output.lines().filter(line -> line.startsWith(RESOLVER_EVENT_PREFIX)).toList();
    assertThat(lifecycleRequests).hasSize(2);
    assertThat(lifecycleRequests.get(0)).contains("filter=[drop-library=true, keep-library=true]");
    assertThat(lifecycleRequests.get(1)).contains("filter=[keep-library=true]");
    assertThat(resolverEvents)
        .as("the TEST lifecycle requests are not delivered to the indexed resolver decorator")
        .isEmpty();
    for (final String request : lifecycleRequests) {
      final String requestToken = requestToken(request);
      assertThat(resolverEvents)
          .as("the indexed decorator should not receive lifecycle request token %s", requestToken)
          .noneMatch(event -> requestToken(event).equals(requestToken));
    }
  }

  private static void assertSessionDecoratorCalls(final String output, final boolean planned) {
    final List<String> requests =
        output.lines().filter(line -> line.startsWith(REQUEST_EVENT_PREFIX)).toList();
    final List<String> callbacks =
        output.lines().filter(line -> line.startsWith("SESSION_DECORATOR ")).toList();
    assertThat(requests).hasSize(2);
    assertThat(callbacks).hasSize(2);
    for (int index = 0; index < requests.size(); index++) {
      final String request = requests.get(index);
      final String callback = callbacks.get(index);
      assertThat(requestToken(callback)).isEqualTo(requestToken(request));
      assertThat(request)
          .contains(
              index == 0
                  ? "filter=[drop-library=true, keep-library=true]"
                  : "filter=[keep-library=true]");
      final boolean planActive = planned && index == 1;
      assertThat(callback).contains(planActive ? "plan=keep-library" : "plan=none");
    }
    final List<String> copyEvents =
        output.lines().filter(line -> line.startsWith("SESSION_COPY ")).toList();
    assertThat(copyEvents).hasSize(planned ? 1 : 0);
    if (planned) {
      assertThat(copyEvents.get(0))
          .contains("requestToken=" + requestToken(requests.get(1)))
          .contains("copied=true");
    }
  }

  private static void assertWorkspaceSubstitution(final String output, final Path replacementJar) {
    final List<String> events =
        output.lines().filter(line -> line.startsWith("WORKSPACE_LOOKUP ")).toList();
    assertThat(events).isNotEmpty();
    for (final String event : events) {
      assertThat(event)
          .contains("artifact=" + GROUP_ID + ":keep-library:jar::" + VERSION)
          .contains("file=" + replacementJar);
      assertThat(requestToken(event))
          .isEqualTo(
              requestToken(
                  output
                      .lines()
                      .filter(line -> line.startsWith(REQUEST_EVENT_PREFIX))
                      .filter(line -> line.contains("filter=[keep-library=true]"))
                      .findFirst()
                      .orElseThrow()));
    }
  }

  private static void assertSessionDecoratorArtifactViews(
      final PhaseSnapshots phases,
      final Path dropJar,
      final String dropHash,
      final Path keepJar,
      final String keepHash,
      final Path replacementJar,
      final String replacementHash) {
    assertArtifacts(phases.before().direct(), DROP, dropJar, dropHash, KEEP, keepJar, keepHash);
    assertArtifacts(phases.before().resolved(), DROP, dropJar, dropHash, KEEP, keepJar, keepHash);
    assertArtifacts(phases.immediate().direct(), KEEP, replacementJar, replacementHash);
    assertArtifacts(phases.immediate().resolved(), KEEP, replacementJar, replacementHash);
    assertArtifacts(phases.intermediate().direct(), KEEP, replacementJar, replacementHash);
    assertThat(phases.intermediate().resolved().size()).isZero();
    assertArtifacts(phases.later().direct(), KEEP, replacementJar, replacementHash);
    assertArtifacts(phases.later().resolved(), KEEP, replacementJar, replacementHash);
    assertSameProject(phases);
  }

  private static String requestToken(final String event) {
    final String marker = "requestToken=";
    final int start = event.indexOf(marker) + marker.length();
    final int end = event.indexOf(' ', start);
    return end < 0 ? event.substring(start) : event.substring(start, end);
  }

  private static void assertResolverProbe(
      final String output,
      final String mode,
      final int expectedCalls,
      final boolean expectBinaryFilter) {
    final List<String> events =
        output.lines().filter(line -> line.startsWith(RESOLVER_EVENT_PREFIX)).toList();
    assertThat(events).hasSize(expectedCalls);
    for (final String event : events) {
      assertThat(event)
          .contains(mode)
          .contains("project=lifecycle-probe-consumer")
          .contains("delegate=org.apache.maven.project.DefaultProjectDependenciesResolver")
          .contains("delegateDistinct=true")
          .contains("graphIn=[" + DROP_AETHER + ", " + KEEP_AETHER + "]")
          .contains(DEPENDENCIES_IN)
          .contains("dependenciesOut=");
      if ("mode=active".equals(mode)) {
        assertThat(event).contains("graphOut=[" + KEEP_AETHER + "]");
      } else {
        assertThat(event).contains("graphOut=[" + DROP_AETHER + ", " + KEEP_AETHER + "]");
      }
      if (expectBinaryFilter) {
        assertThat(event).contains(DROP_AETHER + "=true").contains(KEEP_AETHER + "=true");
      } else {
        assertThat(event).contains(DROP_AETHER + "=false").contains(KEEP_AETHER + "=false");
      }
      final String dependenciesIn = event.substring(event.indexOf(DEPENDENCIES_IN));
      final String dependenciesBefore =
          dependenciesIn.substring(
              DEPENDENCIES_IN.length(), dependenciesIn.indexOf(DEPENDENCIES_OUT));
      final String dependenciesAfter =
          dependenciesIn.substring(
              dependenciesIn.indexOf(DEPENDENCIES_OUT) + DEPENDENCIES_OUT.length());
      assertThat(dependenciesAfter).isEqualTo(dependenciesBefore);
      if (!expectBinaryFilter) {
        assertThat(dependenciesBefore).isEqualTo("[]");
      }
    }
  }

  private static void assertResolverProbeFilters(
      final String output, final List<Boolean> expectedFilters) {
    final List<String> events =
        output.lines().filter(line -> line.startsWith(RESOLVER_EVENT_PREFIX)).toList();
    assertThat(events).hasSize(expectedFilters.size());
    for (int index = 0; index < events.size(); index++) {
      final String event = events.get(index);
      final boolean expectedBinaryFilter = expectedFilters.get(index);
      assertThat(event)
          .contains("mode=active")
          .contains("project=lifecycle-probe-consumer")
          .contains("delegate=org.apache.maven.project.DefaultProjectDependenciesResolver")
          .contains("delegateDistinct=true")
          .contains("graphIn=[" + DROP_AETHER + ", " + KEEP_AETHER + "]")
          .contains("graphOut=[" + KEEP_AETHER + "]");
      assertThat(event)
          .contains(DROP_AETHER + "=" + expectedBinaryFilter)
          .contains(KEEP_AETHER + "=" + expectedBinaryFilter);
      final String dependencyViews = event.substring(event.indexOf(DEPENDENCIES_IN));
      final String dependenciesBefore =
          dependencyViews.substring(
              DEPENDENCIES_IN.length(), dependencyViews.indexOf(DEPENDENCIES_OUT));
      final String dependenciesAfter =
          dependencyViews.substring(
              dependencyViews.indexOf(DEPENDENCIES_OUT) + DEPENDENCIES_OUT.length());
      assertThat(dependenciesAfter).isEqualTo(dependenciesBefore);
      if (!expectedBinaryFilter) {
        assertThat(dependenciesBefore).isEqualTo("[]");
      }
    }
  }

  private static void assertBaseline(
      final PhaseSnapshots phases,
      final Path dropJar,
      final String dropHash,
      final Path keepJar,
      final String keepHash) {
    for (final Snapshot snapshot : List.of(phases.before(), phases.immediate(), phases.later())) {
      assertArtifacts(snapshot.direct(), DROP, dropJar, dropHash, KEEP, keepJar, keepHash);
      assertArtifacts(snapshot.resolved(), DROP, dropJar, dropHash, KEEP, keepJar, keepHash);
    }
    assertArtifacts(
        phases.intermediate().direct(), DROP, dropJar, dropHash, KEEP, keepJar, keepHash);
    assertThat(phases.intermediate().resolved().size()).isZero();
    assertSameProject(phases);
    assertThat(phases.before().direct().collectionIdentity())
        .isEqualTo(phases.later().direct().collectionIdentity());
  }

  private static void assertResolvedOnlyControl(
      final PhaseSnapshots phases,
      final Path dropJar,
      final String dropHash,
      final Path keepJar,
      final String keepHash,
      final Path replacementJar,
      final String replacementHash) {
    assertArtifacts(phases.before().direct(), DROP, dropJar, dropHash, KEEP, keepJar, keepHash);
    assertArtifacts(
        phases.immediate().direct(),
        DROP,
        dropJar,
        dropHash,
        KEEP,
        replacementJar,
        replacementHash);
    assertArtifacts(
        phases.intermediate().direct(),
        DROP,
        dropJar,
        dropHash,
        KEEP,
        replacementJar,
        replacementHash);
    assertArtifacts(
        phases.later().direct(), DROP, dropJar, dropHash, KEEP, replacementJar, replacementHash);
    assertThat(phases.immediate().direct().collectionIdentity())
        .isEqualTo(phases.before().direct().collectionIdentity());
    assertThat(phases.intermediate().direct().collectionIdentity())
        .isEqualTo(phases.before().direct().collectionIdentity());
    assertThat(phases.later().direct().collectionIdentity())
        .isEqualTo(phases.before().direct().collectionIdentity());

    assertArtifacts(phases.immediate().resolved(), KEEP, replacementJar, replacementHash);
    assertThat(phases.intermediate().resolved().size()).isZero();
    assertArtifacts(phases.later().resolved(), KEEP, replacementJar, replacementHash);
    assertThat(phases.before().resolved().artifacts()).containsKey(DROP);
    assertSameProject(phases);
  }

  private static void assertDirectMutationPersistsAcrossLaterResolution(
      final PhaseSnapshots phases,
      final Path dropJar,
      final String dropHash,
      final Path keepJar,
      final String keepHash,
      final Path replacementJar,
      final String replacementHash) {
    assertArtifacts(phases.before().direct(), DROP, dropJar, dropHash, KEEP, keepJar, keepHash);
    assertArtifacts(phases.immediate().direct(), KEEP, replacementJar, replacementHash);
    assertArtifacts(phases.intermediate().direct(), KEEP, replacementJar, replacementHash);
    assertArtifacts(phases.immediate().resolved(), KEEP, replacementJar, replacementHash);
    assertThat(phases.intermediate().resolved().size()).isZero();
    assertThat(phases.immediate().resolved().artifacts().get(KEEP).sha256()).isNotEqualTo(keepHash);
    assertThat(phases.before().direct().collectionIdentity())
        .isNotEqualTo(phases.immediate().direct().collectionIdentity());
    assertThat(phases.intermediate().direct().artifacts()).doesNotContainKey(DROP);

    assertArtifacts(phases.later().direct(), KEEP, replacementJar, replacementHash);
    assertArtifacts(phases.later().resolved(), KEEP, keepJar, keepHash);
    assertSameProject(phases);
  }

  private static void assertSameProject(final PhaseSnapshots phases) {
    assertSameProjectInstance(phases);
  }

  private static void assertSameProjectInstance(final PhaseSnapshots phases) {
    final int projectIdentity = phases.before().projectIdentity();
    assertThat(phases.all()).extracting(Snapshot::projectIdentity).containsOnly(projectIdentity);
    assertThat(phases.all())
        .extracting(Snapshot::projectCoordinate)
        .containsOnly("" + GROUP_ID + ":lifecycle-probe-consumer");
    assertThat(phases.before().resolutionScope()).isEqualTo(TEST_RESOLUTION_SCOPE);
    assertThat(phases.immediate().resolutionScope()).isEqualTo(TEST_RESOLUTION_SCOPE);
    assertThat(phases.intermediate().resolutionScope()).isEqualTo("NONE");
    assertThat(phases.later().resolutionScope()).isEqualTo(TEST_RESOLUTION_SCOPE);
  }

  private static void assertArtifacts(
      final View view, final String coordinate, final Path file, final String sha256) {
    assertArtifacts(view, List.of(new ExpectedArtifact(coordinate, file, sha256)));
  }

  private static void assertArtifacts(
      final View view,
      final String firstCoordinate,
      final Path firstFile,
      final String firstSha256,
      final String secondCoordinate,
      final Path secondFile,
      final String secondSha256) {
    assertArtifacts(
        view,
        List.of(
            new ExpectedArtifact(firstCoordinate, firstFile, firstSha256),
            new ExpectedArtifact(secondCoordinate, secondFile, secondSha256)));
  }

  private static void assertArtifacts(
      final View view, final List<ExpectedArtifact> expectedArtifacts) {
    assertThat(view.size()).isEqualTo(expectedArtifacts.size());
    assertThat(view.artifacts().keySet())
        .containsExactlyInAnyOrder(
            expectedArtifacts.stream().map(ExpectedArtifact::coordinate).toArray(String[]::new));
    for (final ExpectedArtifact expected : expectedArtifacts) {
      final ArtifactState artifact = view.artifacts().get(expected.coordinate());
      assertThat(Path.of(artifact.file())).isEqualTo(expected.file());
      assertThat(artifact.sha256()).isEqualTo(expected.sha256());
    }
  }

  private static void assertDirectMembershipUnchanged(
      final Snapshot beforeResolverRequest, final Snapshot afterResolverRequest) {
    assertThat(afterResolverRequest.direct().collectionIdentity())
        .isEqualTo(beforeResolverRequest.direct().collectionIdentity());
    assertThat(afterResolverRequest.direct().artifacts().keySet())
        .containsExactlyInAnyOrderElementsOf(beforeResolverRequest.direct().artifacts().keySet());
    beforeResolverRequest
        .direct()
        .artifacts()
        .forEach(
            (coordinate, artifact) ->
                assertThat(afterResolverRequest.direct().artifacts().get(coordinate).identity())
                    .isEqualTo(artifact.identity()));
  }

  private static PhaseSnapshots phaseSnapshots(final Path directory, final String mode)
      throws IOException {
    return new PhaseSnapshots(
        Snapshot.read(directory.resolve(mode + "-before.tsv")),
        Snapshot.read(directory.resolve(mode + "-immediate.tsv")),
        Snapshot.read(directory.resolve(mode + "-intermediate.tsv")),
        Snapshot.read(directory.resolve(mode + "-later.tsv")));
  }

  private static Path repositoryRoot() {
    Path current = Path.of(System.getProperty("user.dir")).toAbsolutePath().normalize();
    while (current != null && !Files.isRegularFile(current.resolve(MAVEN_WRAPPER))) {
      current = current.getParent();
    }
    if (current == null) {
      throw new IllegalStateException(
          "Could not find repository Maven wrapper from test directory");
    }
    return current;
  }

  private Path copyLifecycleFixture(final Path repositoryRoot) throws IOException {
    return copyLifecycleFixture(
        repositoryRoot, temporaryDirectory.resolve("lifecycle-probe-fixture"));
  }

  private static Path copyLifecycleFixture(final Path repositoryRoot, final Path destination)
      throws IOException {
    final Path source =
        repositoryRoot.resolve("dependency-elider-maven-plugin/src/test/fixtures/lifecycle-probe");
    copyDirectoryTree(source, destination);
    final Path testSources = repositoryRoot.resolve("dependency-elider-maven-plugin/src/test/java");
    for (final String module :
        List.of("helper-plugin", "resolver-extension", "plan-seed-extension")) {
      final Path pom = destination.resolve(module).resolve(POM_XML);
      final String contents = Files.readString(pom);
      Files.writeString(
          pom,
          contents.replace(
              "${project.basedir}/../../../java", testSources.toString().replace('\\', '/')));
    }
    return destination;
  }

  private static Path copySeedRepository(final Path evidenceDirectory) throws IOException {
    final Path repository = evidenceDirectory.resolve("repository");
    copyDirectoryTree(seedRepository, repository);
    return repository;
  }

  private static void copyDirectoryTree(final Path source, final Path destination)
      throws IOException {
    try (Stream<Path> paths = Files.walk(source)) {
      for (final Path path : paths.toList()) {
        final Path copiedPath = destination.resolve(source.relativize(path));
        if (Files.isDirectory(path)) {
          Files.createDirectories(copiedPath);
        } else {
          Files.copy(path, copiedPath);
        }
      }
    }
  }

  private static Path writeSettings(final Path evidenceDirectory)
      throws IOException, XMLStreamException {
    final String repositoryUri =
        Path.of(System.getProperty("user.home"), ".m2/repository").toUri().toASCIIString();
    final Path settings = evidenceDirectory.resolve("settings.xml");
    try (OutputStream output = Files.newOutputStream(settings)) {
      final XMLStreamWriter xml =
          XMLOutputFactory.newFactory().createXMLStreamWriter(output, "UTF-8");
      try {
        xml.writeStartDocument("UTF-8", "1.0");
        xml.writeStartElement("settings");
        xml.writeDefaultNamespace("http://maven.apache.org/SETTINGS/1.2.0");
        xml.writeNamespace("xsi", XMLConstants.W3C_XML_SCHEMA_INSTANCE_NS_URI);
        xml.writeAttribute(
            "xsi",
            XMLConstants.W3C_XML_SCHEMA_INSTANCE_NS_URI,
            "schemaLocation",
            "http://maven.apache.org/SETTINGS/1.2.0 https://maven.apache.org/xsd/settings-1.2.0.xsd");
        writeRepositoryProfile(xml, repositoryUri);
        xml.writeEndElement();
        xml.writeEndDocument();
      } finally {
        xml.close();
      }
    }
    return settings;
  }

  private static void writeRepositoryProfile(final XMLStreamWriter xml, final String repositoryUri)
      throws XMLStreamException {
    xml.writeStartElement("profiles");
    xml.writeStartElement("profile");
    writeTextElement(xml, "id", "cached-local-repository");
    xml.writeStartElement("repositories");
    writeRepository(xml, "repository", "cached-local-repository", repositoryUri);
    xml.writeEndElement();
    xml.writeStartElement("pluginRepositories");
    writeRepository(xml, "pluginRepository", "cached-local-plugins", repositoryUri);
    xml.writeEndElement();
    xml.writeEndElement();
    xml.writeEndElement();
    xml.writeStartElement("activeProfiles");
    writeTextElement(xml, "activeProfile", "cached-local-repository");
    xml.writeEndElement();
  }

  private static void writeRepository(
      final XMLStreamWriter xml,
      final String element,
      final String identifier,
      final String repositoryUri)
      throws XMLStreamException {
    xml.writeStartElement(element);
    writeTextElement(xml, "id", identifier);
    writeTextElement(xml, "url", repositoryUri);
    xml.writeEndElement();
  }

  private static void writeTextElement(
      final XMLStreamWriter xml, final String name, final String value) throws XMLStreamException {
    xml.writeStartElement(name);
    xml.writeCharacters(value);
    xml.writeEndElement();
  }

  private static String run(
      final Path repositoryRoot,
      final Path wrapper,
      final Path settings,
      final Path localRepository,
      final Path logFile,
      final Duration timeout,
      final String... arguments)
      throws IOException, InterruptedException {
    return runFromDirectory(
        repositoryRoot, wrapper, settings, localRepository, logFile, timeout, arguments);
  }

  private record SubprocessExecution(int exitCode, String output) {}

  @SuppressWarnings("PMD.DoNotUseThreads")
  private static SubprocessExecution executeSubprocess(
      final Path workingDirectory,
      final Path wrapper,
      final Path settings,
      final Path localRepository,
      final Path logFile,
      final Duration timeout,
      final String... arguments)
      throws IOException, InterruptedException {
    Files.createDirectories(logFile.getParent());
    final List<String> command = new ArrayList<>();
    command.add(wrapper.toString());
    command.add("--batch-mode");
    command.add("--no-transfer-progress");
    command.add("-s");
    command.add(settings.toString());
    command.add("-Dmaven.repo.local=" + localRepository);
    command.addAll(List.of(arguments));
    final ProcessBuilder processBuilder =
        new ProcessBuilder(command)
            .directory(workingDirectory.toFile())
            .redirectErrorStream(true)
            .redirectOutput(logFile.toFile());
    processBuilder.environment().put("JAVA_HOME", System.getProperty("java.home"));
    final Process process = processBuilder.start();
    final boolean exited;
    try {
      exited = process.waitFor(timeout.toMillis(), TimeUnit.MILLISECONDS);
    } catch (InterruptedException interrupted) {
      terminate(process);
      Thread.currentThread().interrupt();
      throw interrupted;
    }
    if (!exited) {
      terminate(process);
      process.waitFor(10, TimeUnit.SECONDS);
      fail("Maven subprocess exceeded " + timeout + "; log retained at " + logFile);
    }
    final String output = Files.readString(logFile);
    return new SubprocessExecution(process.exitValue(), output);
  }

  private static String runFromDirectory(
      final Path workingDirectory,
      final Path wrapper,
      final Path settings,
      final Path localRepository,
      final Path logFile,
      final Duration timeout,
      final String... arguments)
      throws IOException, InterruptedException {
    final SubprocessExecution execution =
        executeSubprocess(
            workingDirectory, wrapper, settings, localRepository, logFile, timeout, arguments);
    if (execution.exitCode() != 0) {
      fail(
          "Maven subprocess exited "
              + execution.exitCode()
              + "; log retained at "
              + logFile
              + "\n"
              + execution.output());
    }
    return execution.output();
  }

  private static String runExpectingFailure(
      final Path workingDirectory,
      final Path wrapper,
      final Path settings,
      final Path localRepository,
      final Path logFile,
      final Duration timeout,
      final String... arguments)
      throws IOException, InterruptedException {
    final SubprocessExecution execution =
        executeSubprocess(
            workingDirectory, wrapper, settings, localRepository, logFile, timeout, arguments);
    if (execution.exitCode() == 0) {
      fail(
          "Maven subprocess unexpectedly succeeded; log retained at "
              + logFile
              + "\n"
              + execution.output());
    }
    return execution.output();
  }

  private static void terminate(final Process process) {
    process.descendants().forEach(ProcessHandle::destroyForcibly);
    process.destroyForcibly();
  }

  private static Path repositoryArtifact(final Path localRepository, final String artifactId) {
    return localRepository.resolve(
        "io/github/spockz/elider/test/"
            + artifactId
            + "/"
            + VERSION
            + "/"
            + artifactId
            + "-"
            + VERSION
            + ".jar");
  }

  private static void writeReplacementJar(final Path output) throws IOException {
    Files.createDirectories(output.getParent());
    try (JarOutputStream jar = new JarOutputStream(Files.newOutputStream(output))) {
      jar.putNextEntry(new JarEntry("fixture/transformed.txt"));
      jar.write("transformed artifact bytes".getBytes(StandardCharsets.UTF_8));
      jar.closeEntry();
    }
  }

  private static String sha256(final Path file) throws IOException {
    try {
      return HexFormat.of()
          .formatHex(MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(file)));
    } catch (NoSuchAlgorithmException exception) {
      throw new IllegalStateException("Java runtime does not provide SHA-256", exception);
    }
  }

  private static void deleteTree(final Path root) throws IOException {
    if (!Files.exists(root)) {
      return;
    }
    try (Stream<Path> paths = Files.walk(root)) {
      for (final Path path : paths.sorted(Comparator.reverseOrder()).toList()) {
        Files.delete(path);
      }
    }
  }

  private record ArtifactState(int identity, String coordinate, String file, String sha256) {}

  private record ExpectedArtifact(String coordinate, Path file, String sha256) {}

  private record View(int collectionIdentity, int size, Map<String, ArtifactState> artifacts) {}

  private record Snapshot(
      String resolutionScope,
      int projectIdentity,
      String projectCoordinate,
      View direct,
      View resolved) {
    static Snapshot read(final Path path) throws IOException {
      final Map<String, MutableView> views = new HashMap<>();
      String resolutionScope = "";
      int projectIdentity = -1;
      String projectCoordinate = "";
      for (final String line : Files.readAllLines(path)) {
        final String[] values = line.split("\\t", -1);
        if ("scope".equals(values[0])) {
          resolutionScope = values[1];
        } else if ("project".equals(values[0])) {
          projectIdentity = Integer.parseInt(values[1]);
          projectCoordinate = values[2];
        } else if ("view".equals(values[0])) {
          views.put(
              values[1], new MutableView(Integer.parseInt(values[2]), Integer.parseInt(values[3])));
        } else if ("artifact".equals(values[0])) {
          views
              .get(values[1])
              .artifacts()
              .put(
                  values[3],
                  new ArtifactState(
                      Integer.parseInt(values[2]), values[3], decodePath(values[4]), values[5]));
        }
      }
      return new Snapshot(
          resolutionScope,
          projectIdentity,
          projectCoordinate,
          views.get("DIRECT").toView(),
          views.get("RESOLVED").toView());
    }

    private static String decodePath(final String encodedPath) {
      if ("<missing>".equals(encodedPath)) {
        return encodedPath;
      }
      return new String(Base64.getDecoder().decode(encodedPath), StandardCharsets.UTF_8);
    }
  }

  private record MutableView(
      int collectionIdentity, int size, Map<String, ArtifactState> artifacts) {
    MutableView(final int collectionIdentity, final int size) {
      this(collectionIdentity, size, new HashMap<>());
    }

    View toView() {
      return new View(collectionIdentity, size, Map.copyOf(artifacts));
    }
  }

  private record PhaseSnapshots(
      Snapshot before, Snapshot immediate, Snapshot intermediate, Snapshot later) {
    List<Snapshot> all() {
      return List.of(before, immediate, intermediate, later);
    }
  }
}
