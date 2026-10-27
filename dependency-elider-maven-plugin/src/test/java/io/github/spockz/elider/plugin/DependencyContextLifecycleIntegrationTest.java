/* WHY: Keeps real lifecycle probes outside the published plugin artifact. */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;

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
import javax.xml.XMLConstants;
import javax.xml.stream.XMLOutputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamWriter;
import org.junit.jupiter.api.Test;

/** Verifies artifact-view changes across a real Maven lifecycle. */
@SuppressWarnings({
  "PMD.AddEmptyString",
  "PMD.AtLeastOneConstructor",
  "PMD.AvoidInstantiatingObjectsInLoops",
  "PMD.AvoidLiteralsInIfCondition",
  "PMD.CommentDefaultAccessModifier",
  "PMD.CommentRequired",
  "PMD.CouplingBetweenObjects",
  "PMD.GodClass",
  "PMD.TooManyMethods",
  "PMD.UnitTestContainsTooManyAsserts",
  "PMD.UseConcurrentHashMap"
})
final class DependencyContextLifecycleIntegrationTest {
  private static final String GROUP_ID = "io.github.spockz.elider.test";

  private static final String VERSION = "1.0.0";

  private static final String DROP = GROUP_ID + ":drop-library:" + VERSION + ":jar:";

  private static final String KEEP = GROUP_ID + ":keep-library:" + VERSION + ":jar:";

  private static final String DROP_AETHER = GROUP_ID + ":drop-library:jar:" + VERSION;

  private static final String KEEP_AETHER = GROUP_ID + ":keep-library:jar:" + VERSION;

  private static final String TREE_GOAL =
      "org.apache.maven.plugins:maven-dependency-plugin:3.8.1:tree";

  private static final String TREE_HEADER = "[INFO] --- dependency:3.8.1:tree";

  private static final String DEPENDENCIES_IN = "dependenciesIn=";

  private static final String DEPENDENCIES_OUT = " dependenciesOut=";

  private static final String RESOLVER_EVENT_PREFIX = "RESOLVER_PROBE ";

  private static final String REQUEST_EVENT_PREFIX = "RESOLVER_REQUEST ";

  private static final String LIFECYCLE_REPLACEMENT_FILE_PROPERTY = "-Dlifecycle.replacementFile=";

  private static final Duration PROCESS_TIMEOUT = Duration.ofSeconds(180);

  @Test
  @SuppressWarnings("PMD.AvoidDuplicateLiterals")
  void lifecycleSnapshotsShowDirectAndResolvedViewsHaveDifferentLaterResolutionBehavior()
      throws Exception {
    final Path repositoryRoot = repositoryRoot();
    final Path fixtureRoot =
        repositoryRoot.resolve("dependency-elider-maven-plugin/src/test/fixtures/lifecycle-probe");
    final Path evidenceDirectory =
        repositoryRoot.resolve("dependency-elider-maven-plugin/target/lifecycle-probe-evidence");
    deleteTree(evidenceDirectory);
    Files.createDirectories(evidenceDirectory);
    final Path localRepository = Files.createDirectories(evidenceDirectory.resolve("repository"));
    final Path settings = writeSettings(evidenceDirectory);
    final Path wrapper = repositoryRoot.resolve("mvnw");

    final String versionOutput =
        run(
            repositoryRoot,
            wrapper,
            settings,
            localRepository,
            evidenceDirectory.resolve("maven-version.log"),
            PROCESS_TIMEOUT,
            "-version");
    assertThat(versionOutput).contains("Apache Maven 3.9.11");

    run(
        repositoryRoot,
        wrapper,
        settings,
        localRepository,
        evidenceDirectory.resolve("fixture-bootstrap.log"),
        PROCESS_TIMEOUT,
        "-f",
        fixtureRoot.resolve("bootstrap/pom.xml").toString(),
        "clean",
        "install");

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
  @SuppressWarnings("PMD.AvoidDuplicateLiterals")
  void resolverDecoratorChangesEachRepeatedTreeOutput() throws Exception {
    final Path repositoryRoot = repositoryRoot();
    final Path fixtureRoot =
        repositoryRoot.resolve("dependency-elider-maven-plugin/src/test/fixtures/lifecycle-probe");
    final Path evidenceDirectory =
        repositoryRoot.resolve("dependency-elider-maven-plugin/target/resolver-probe-evidence");
    deleteTree(evidenceDirectory);
    Files.createDirectories(evidenceDirectory);
    final Path localRepository = Files.createDirectories(evidenceDirectory.resolve("repository"));
    final Path settings = writeSettings(evidenceDirectory);
    final Path wrapper = repositoryRoot.resolve("mvnw");
    final Path consumer = fixtureRoot.resolve("consumer");
    final Path consumerPom = consumer.resolve("pom.xml");

    final String versionOutput =
        run(
            repositoryRoot,
            wrapper,
            settings,
            localRepository,
            evidenceDirectory.resolve("maven-version.log"),
            PROCESS_TIMEOUT,
            "-version");
    assertThat(versionOutput).contains("Apache Maven 3.9.11");
    run(
        repositoryRoot,
        wrapper,
        settings,
        localRepository,
        evidenceDirectory.resolve("fixture-bootstrap.log"),
        PROCESS_TIMEOUT,
        "-f",
        fixtureRoot.resolve("bootstrap/pom.xml").toString(),
        "clean",
        "install");

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
    final Path fixtureRoot =
        repositoryRoot.resolve("dependency-elider-maven-plugin/src/test/fixtures/lifecycle-probe");
    final Path evidenceDirectory =
        repositoryRoot.resolve(
            "dependency-elider-maven-plugin/target/production-extension-evidence");
    deleteTree(evidenceDirectory);
    Files.createDirectories(evidenceDirectory);
    final Path localRepository = Files.createDirectories(evidenceDirectory.resolve("repository"));
    final Path settings = writeSettings(evidenceDirectory);
    final Path wrapper = repositoryRoot.resolve("mvnw");

    run(
        repositoryRoot,
        wrapper,
        settings,
        localRepository,
        evidenceDirectory.resolve("production-install.log"),
        PROCESS_TIMEOUT,
        "-f",
        repositoryRoot.resolve("pom.xml").toString(),
        "-pl",
        "dependency-elider-maven-plugin",
        "-am",
        "install",
        "-DskipTests");
    run(
        repositoryRoot,
        wrapper,
        settings,
        localRepository,
        evidenceDirectory.resolve("fixture-bootstrap.log"),
        PROCESS_TIMEOUT,
        "-f",
        fixtureRoot.resolve("bootstrap/pom.xml").toString(),
        "clean",
        "install");

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
      Files.copy(fixtureRoot.resolve("consumer/pom.xml"), consumer.resolve("pom.xml"));
      final boolean extensionEnabled = "production-positive".equals(mode);
      final Path extensionsDirectory = Files.createDirectories(consumer.resolve(".mvn"));
      writeConsumerExtensions(extensionsDirectory.resolve("extensions.xml"), extensionEnabled);
      final Path snapshots = evidenceDirectory.resolve(mode + "/snapshots");
      final Path modeLog = evidenceDirectory.resolve(mode + ".log");
      final List<String> properties =
          List.of(
              "-Dlifecycle.mode=baseline",
              "-Dlifecycle.reportDirectory=" + snapshots,
              LIFECYCLE_REPLACEMENT_FILE_PROPERTY + replacementJar,
              "-f",
              consumer.resolve("pom.xml").toString());
      runFromDirectory(
          consumer,
          wrapper,
          settings,
          localRepository,
          modeLog,
          PROCESS_TIMEOUT,
          Stream.concat(properties.stream(), Stream.of("prepare-package")).toArray(String[]::new));
      assertThat(Files.readString(modeLog)).contains("BUILD SUCCESS");
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
            .contains("io.github.spockz.elider.plugin.EliderRepositorySessionDecorator");
      }
      assertThat(
              jar.getJarEntry(
                  "io/github/spockz/elider/plugin/EliderRepositorySessionDecorator.class"))
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
    assertThat(phases.before().resolutionScope()).isEqualTo("TEST");
    assertThat(phases.immediate().resolutionScope()).isEqualTo("TEST");
    assertThat(phases.intermediate().resolutionScope()).isEqualTo("NONE");
    assertThat(phases.later().resolutionScope()).isEqualTo("TEST");
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
    while (current != null && !Files.isRegularFile(current.resolve("mvnw"))) {
      current = current.getParent();
    }
    if (current == null) {
      throw new IllegalStateException(
          "Could not find repository Maven wrapper from test directory");
    }
    return current;
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

  @SuppressWarnings("PMD.DoNotUseThreads")
  private static String runFromDirectory(
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
    if (process.exitValue() != 0) {
      fail(
          "Maven subprocess exited "
              + process.exitValue()
              + "; log retained at "
              + logFile
              + "\n"
              + output);
    }
    return output;
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
