// WHY: Verifies goal skipping and real artifact-view mutation through the Maven goal.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.scanner.BytecodeReferenceScan;
import io.github.spockz.elider.trimmer.ArtifactDigests;
import io.github.spockz.elider.trimmer.ArtifactTrimRecord;
import io.github.spockz.elider.trimmer.DependencyJarTrimmer;
import io.github.spockz.elider.trimmer.JdkApiClassPoolReader;
import io.github.spockz.elider.trimmer.TrimAnalysisSession;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Proxy;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.FileTime;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.zip.CRC32;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.artifact.DefaultArtifact;
import org.apache.maven.artifact.handler.DefaultArtifactHandler;
import org.apache.maven.execution.DefaultMavenExecutionRequest;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.model.Build;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugin.logging.Log;
import org.apache.maven.plugin.logging.SystemStreamLog;
import org.apache.maven.project.MavenProject;
import org.apache.maven.toolchain.ToolchainManager;
import org.codehaus.plexus.PlexusContainer;
import org.eclipse.aether.DefaultRepositorySystemSession;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.ModuleVisitor;
import org.objectweb.asm.Opcodes;

/** Verifies goal skipping and trace-based artifact-view mutation. */
// This fixture covers Maven, archive, bytecode, and SBOM integration APIs.
@SuppressWarnings({
  "PMD.ExcessiveImports",
  "PMD.AvoidAccessibilityAlteration",
  "PMD.AvoidDuplicateLiterals",
  "PMD.TooManyMethods",
  "PMD.GodClass",
  "PMD.CouplingBetweenObjects",
  "PMD.UnitTestContainsTooManyAsserts",
  "PMD.LawOfDemeter",
  "PMD.ShortVariable",
  "PMD.AvoidInstantiatingObjectsInLoops",
  "PMD.CyclomaticComplexity",
  "PMD.NcssCount"
})
final class ElideMojoTest {
  /** Plexus method used by the Maven session fixture proxy. */
  private static final String LOOKUP_METHOD = "lookup";

  /** Root module descriptor entry used by projected fixture archives. */
  private static final String MODULE_INFO_CLASS = "module-info.class";

  /** Temporary directory for synthetic JARs and runtime traces. */
  @TempDir private Path tempDir;

  /** Creates the focused test fixture. */
  @SuppressWarnings({"PMD.UncommentedEmptyConstructor", "PMD.CommentDefaultAccessModifier"})
  ElideMojoTest() {}

  @Test
  void skipReturnsWithoutAccessingProjectState() throws ReflectiveOperationException {
    final ElideMojo mojo = newMojo();
    final Field skip = ElideMojo.class.getDeclaredField("skip");
    skip.setAccessible(true);
    skip.setBoolean(mojo, true);

    assertThatCode(mojo::execute).doesNotThrowAnyException();
  }

  @Test
  void skippedElisionPreservesLastSuccessfulReportSnapshot()
      throws IOException, ReflectiveOperationException, MojoFailureException {
    final Path snapshot = tempDir.resolve("previous-report.json");
    final MavenElisionReportSnapshot previous = previousSnapshot();
    MavenElisionReportWriter.write(snapshot, previous);
    final ElideMojo mojo = newMojo();
    final MavenProject project = newProject();
    set(mojo, "project", project);
    mojo.setLog(new SystemStreamLog());
    set(mojo, "skip", true);
    set(mojo, "summaryFile", snapshot.toFile());
    seedResolverPlan(mojo, project, "stale-before-skip.jar");

    mojo.execute();

    assertLastSuccessfulSnapshotRemains(snapshot, previous);
    assertThat(resolverPlan(mojo, project).replacements()).isEmpty();
  }

  @Test
  void noTrimExecutionClearsThePriorResolverPlan()
      throws IOException, ReflectiveOperationException, MojoFailureException {
    final Artifact used = artifact("used", "used/Entry.class");
    final MavenProject project = project(used, new LinkedHashSet<>(List.of(used)));
    final ElideMojo mojo = newMojo();
    set(mojo, "project", project);
    set(mojo, "traceFiles", List.of(writeTrace("used.Entry\n").toFile()));
    set(mojo, "reportFile", tempDir.resolve("no-trim-report.json").toFile());
    seedResolverPlan(mojo, project, "stale-before-no-trim.jar");

    mojo.execute();

    assertThat(resolverPlan(mojo, project).replacements()).isEmpty();
  }

  @Test
  void failedPlanPublicationRestoresPriorOutputsViewsAndResolverPayload()
      throws IOException, ReflectiveOperationException {
    final Path originalJar =
        compileJarSources(
            "publication-rollback",
            Map.of("used/Entry.java", "package used; public class Entry {}"),
            null);
    final Artifact used = runtimeArtifact("used", originalJar);
    final MavenProject project = project(used, new LinkedHashSet<>(List.of(used)));
    project.getProperties().setProperty("maven.compiler.release", "21");
    final Build build = new Build();
    build.setDirectory(tempDir.resolve("publication-rollback-build").toString());
    project.setBuild(build);
    final ElideMojo mojo = newMojo();
    final Path classUsageReport = tempDir.resolve("class-usage-report.json");
    final Path summaryReport = tempDir.resolve("summary-report.json");
    final Path sbomReport = tempDir.resolve("sbom-report.json");
    final byte[] previousReport =
        "previous class report".getBytes(java.nio.charset.StandardCharsets.UTF_8);
    final byte[] previousSummary =
        "previous summary".getBytes(java.nio.charset.StandardCharsets.UTF_8);
    final byte[] previousSbom = "previous SBOM".getBytes(java.nio.charset.StandardCharsets.UTF_8);
    Files.write(classUsageReport, previousReport);
    Files.write(summaryReport, previousSummary);
    Files.write(sbomReport, previousSbom);
    final Set<Artifact> previousResolved = project.getArtifacts();
    final Set<Artifact> previousDirect = project.getDependencyArtifacts();
    final java.io.File previousArtifactFile = used.getFile();
    set(mojo, "project", project);
    set(mojo, "traceFiles", List.of(writeTrace("used.Entry\n").toFile()));
    set(mojo, "trimJars", true);
    set(mojo, "reportFile", classUsageReport.toFile());
    set(mojo, "summaryFile", summaryReport.toFile());
    set(mojo, "sbomFile", sbomReport.toFile());
    seedResolverPlan(mojo, project, "stale-before-output-failure.jar");
    final MavenSession session = (MavenSession) fieldValue(mojo, "session");
    final Object previousPayload =
        session
            .getRepositorySession()
            .getData()
            .get(ResolverArtifactPlanPublisher.SESSION_DATA_KEY);
    set(
        mojo,
        "planPublication",
        (ElideMojo.PlanPublication)
            (ignoredSession, ignoredProject, ignoredRecords, ignoredProjection) -> {
              throw new IOException("injected resolver plan publication failure");
            });

    assertThatThrownBy(mojo::execute)
        .isInstanceOf(MojoFailureException.class)
        .hasMessageContaining("injected resolver plan publication failure");
    assertThat(Files.readAllBytes(classUsageReport)).isEqualTo(previousReport);
    assertThat(Files.readAllBytes(summaryReport)).isEqualTo(previousSummary);
    assertThat(Files.readAllBytes(sbomReport)).isEqualTo(previousSbom);
    assertThat(project.getArtifacts()).containsExactlyElementsOf(previousResolved);
    assertThat(project.getArtifacts().iterator().next()).isSameAs(used);
    assertThat(project.getDependencyArtifacts()).containsExactlyElementsOf(previousDirect);
    assertThat(project.getDependencyArtifacts().iterator().next()).isSameAs(used);
    assertThat(used.getFile()).isEqualTo(previousArtifactFile);
    assertThat(EffectiveOutputCacheTestFiles.cacheManifest(project)).doesNotExist();
    assertThat(
            session
                .getRepositorySession()
                .getData()
                .get(ResolverArtifactPlanPublisher.SESSION_DATA_KEY))
        .isSameAs(previousPayload);
  }

  @Test
  void failedElisionPreservesLastSuccessfulReportSnapshot()
      throws IOException, ReflectiveOperationException {
    final Path snapshot = tempDir.resolve("previous-report.json");
    final MavenElisionReportSnapshot previous = previousSnapshot();
    MavenElisionReportWriter.write(snapshot, previous);
    final MavenProject project = newProject();
    project.setArtifacts(Set.of());
    final ElideMojo mojo = newMojo();
    mojo.setLog(new SystemStreamLog());
    set(mojo, "project", project);
    set(mojo, "traceFiles", List.of(tempDir.resolve("missing-trace.lst").toFile()));
    set(mojo, "summaryFile", snapshot.toFile());

    assertThatThrownBy(mojo::execute).isInstanceOf(MojoFailureException.class);
    assertLastSuccessfulSnapshotRemains(snapshot, previous);
  }

  @Test
  void retainsCompileVisibleArtifactsInResolvedAndDirectViews()
      throws IOException, ReflectiveOperationException, MojoFailureException {
    final Artifact used =
        runtimeArtifact(
            "used",
            compileJarSources(
                "used", Map.of("Sample.java", "package used; public class Sample {}"), null));
    final Artifact unused =
        runtimeArtifact(
            "unused",
            compileJarSources(
                "unused-valid-jar",
                Map.of("unused/Idle.java", "package unused; public class Idle {}"),
                null));
    final Set<Artifact> resolved = new LinkedHashSet<>(List.of(used, unused));
    final Set<Artifact> direct = new LinkedHashSet<>(List.of(used, unused));
    final MavenProject project = newProject();
    project.setArtifacts(resolved);
    project.setDependencyArtifacts(direct);
    final RecordingMavenLog log = new RecordingMavenLog();
    execute(project, "used/Sample\n", log);

    assertThat(project.getArtifacts()).isNotSameAs(resolved);
    assertThat(project.getArtifacts()).containsExactlyInAnyOrder(used, unused);
    assertThat(log.messages())
        .contains(
            "  Classes removed: 0 / N/A (N/A; stage not run)",
            "  Program classes removed with dropped JARs: 0 (uncompressed .class entry payload"
                + " bytes: 0 B; excludes module descriptors and archive sanitation metadata)");
    assertThat(project.getDependencyArtifacts()).isSameAs(direct);
    assertThat(project.getDependencyArtifacts()).containsExactlyInAnyOrder(used, unused);
    final Artifact addedLater = artifact("later", "later/Added.class");
    project.getArtifacts().add(addedLater);
    project.getDependencyArtifacts().add(addedLater);
    assertThat(project.getArtifacts()).contains(addedLater);
    assertThat(project.getDependencyArtifacts()).contains(addedLater);
  }

  @Test
  void traceApplicationClassWithoutProductionOutputDoesNotBlockElision()
      throws IOException, ReflectiveOperationException, MojoFailureException {
    final Artifact used =
        runtimeArtifact(
            "used-app-trace",
            compileJarSources(
                "used-app-trace-jar",
                Map.of("used/Entry.java", "package used; public class Entry {}"),
                null));
    final MavenProject project = project(used, new LinkedHashSet<>(List.of(used)));
    final RecordingMavenLog log = new RecordingMavenLog();

    execute(project, "sample.App\nused.Entry\n", log);

    assertThat(project.getArtifacts()).contains(used);
    assertThat(log.messages()).contains("  Whole artifacts: 0 / 1 (0.0%)");
  }

  @Test
  void trimJarsRedirectsTheArtifactAndWritesPedigreeSbom()
      throws IOException, ReflectiveOperationException, MojoFailureException {
    final Artifact runtime = compiledArtifact();
    final Artifact directRuntime =
        runtimeArtifact("runtime-dependency", runtime.getFile().toPath());
    final Artifact unusedRuntime =
        runtimeArtifact(
            "unused-runtime",
            compileJarSources(
                "unused-runtime-valid-jar",
                Map.of("unused/Entry.java", "package unused; public class Entry {}"),
                null));
    final MavenProject project =
        project(runtime, new LinkedHashSet<>(List.of(directRuntime)), unusedRuntime);
    final Set<Artifact> directBefore = project.getDependencyArtifacts();
    project.setGroupId("org.example");
    project.setArtifactId("consumer");
    project.setVersion("1.0");
    project.setName("Consumer");
    project.getProperties().setProperty("maven.compiler.release", "21");
    final Build build = new Build();
    build.setDirectory(tempDir.resolve("build").toString());
    build.setOutputDirectory(tempDir.resolve("build/classes").toString());
    project.setBuild(build);
    final Path original = runtime.getFile().toPath();
    final ElideMojo mojo = newMojo();
    final RecordingMavenLog log = new RecordingMavenLog();
    mojo.setLog(log);
    set(mojo, "project", project);
    set(mojo, "traceFiles", List.of(writeTrace("sample.Keep\n").toFile()));
    set(mojo, "reportFile", tempDir.resolve("trim-report.json").toFile());
    set(mojo, "trimJars", true);
    set(mojo, "sbomFile", tempDir.resolve("build/dependency-elider-sbom.cdx.json").toFile());
    set(mojo, "baselineSbomFile", tempDir.resolve("build/baseline-sbom.cdx.json").toFile());
    set(mojo, "cveCacheDirectory", tempDir.resolve("vulnerability-cache").toFile());
    final VulnerabilityMappingConfig mapping = new VulnerabilityMappingConfig();
    mapping.setCveId("CVE-2026-10001");
    mapping.setGroupId("org.example");
    mapping.setArtifactId("runtime-dependency");
    mapping.setVersion("1.0");
    mapping.setVersionRangeSpec("[1.0,2.0)");
    mapping.setVulnerableClasses(List.of("sample.Drop"));
    mapping.setConfidenceLevel("HIGH");
    set(mojo, "vulnerabilityMappings", List.of(mapping));
    final ObjectMapper cacheMapper = new ObjectMapper();
    final ObjectNode cachedMapping = cacheMapper.createObjectNode();
    final ObjectNode cacheCoordinate = cachedMapping.putObject("affectedCoordinate");
    cacheCoordinate.put("groupId", "org.example");
    cacheCoordinate.put("artifactId", "runtime-dependency");
    cacheCoordinate.put("version", "1.0");
    cacheCoordinate.put("type", "jar");
    cacheCoordinate.put("classifier", "");
    cacheCoordinate.put("scope", "runtime");
    cachedMapping.put("cveId", "CVE-2026-10001");
    cachedMapping.put("versionRangeSpec", "[1.0]");
    cachedMapping.putArray("vulnerableClasses").add("sample.Helper");
    cachedMapping.putNull("sourceAdvisoryUrl");
    cachedMapping.put("confidenceLevel", "HIGH");
    Files.createDirectories(tempDir.resolve("vulnerability-cache"));
    final ObjectNode cacheDocument = cacheMapper.createObjectNode();
    cacheDocument.putArray("mappings").add(cachedMapping);
    cacheMapper.writeValue(
        tempDir.resolve("vulnerability-cache/index.json").toFile(), cacheDocument);

    mojo.execute();

    final ResolverArtifactPlan plan = resolverPlan(mojo, project);
    assertThat(plan.replacements())
        .containsEntry(
            new ResolverArtifactPlan.ArtifactIdentity(
                "org.example", "runtime-dependency", "1.0", "jar", ""),
            new ResolverArtifactPlan.Replacement(
                runtime.getFile().toPath(), ArtifactFileDigest.sha256(runtime.getFile().toPath())));

    assertThat(runtime.getFile().toPath()).isNotEqualTo(original).isRegularFile();
    assertThat(log.messages())
        .contains(
            "  Program classes pruned from retained JARs: 1 (uncompressed omitted .class "
                + "entry payload bytes: "
                + MavenElisionReportWriter.formatBytes(
                    classEntrySize(original, "sample/Drop.class"))
                + "; excludes module descriptors and archive sanitation metadata)");
    assertThat(log.messages()).doesNotContain("  Classes removed: 0 / N/A (N/A; stage not run)");
    assertThat(log.messages())
        .contains(
            "POM vulnerability mapping overrides cached mapping for "
                + "CVE-2026-10001 org.example:runtime-dependency:jar:1.0")
        .noneMatch(message -> message.contains("sample.Drop"));
    assertThat(log.messages())
        .anyMatch(line -> line.startsWith("  Mitigated CVEs (vulnerable code pruned by trimming):"))
        .contains("    CVE-2026-10001 org.example:runtime-dependency:jar:1.0");
    assertThat(directRuntime.getFile().toPath()).isEqualTo(runtime.getFile().toPath());
    assertThat(project.getArtifacts()).contains(runtime);
    assertThat(project.getArtifacts()).contains(unusedRuntime);
    assertThat(project.getDependencyArtifacts()).isSameAs(directBefore).contains(directRuntime);
    final MavenElisionReportSnapshot report =
        MavenElisionReportWriter.read(tempDir.resolve("build/dependency-elider-report.json"));
    assertThat(report.wholeArtifactsDropped()).isZero();
    assertThat(report.rawDroppedCoordinates())
        .contains("org.example:unused-runtime:jar:1.0 (runtime)");
    try (JarFile trimmed = new JarFile(runtime.getFile())) {
      assertThat(trimmed.getEntry("sample/Keep.class")).isNotNull();
      assertThat(trimmed.getEntry("sample/Helper.class")).isNotNull();
      assertThat(trimmed.getEntry("sample/Drop.class")).isNull();
    }
    assertThat(tempDir.resolve("build/dependency-elider-sbom.cdx.json")).isRegularFile();
    assertThat(tempDir.resolve("build/baseline-sbom.cdx.json")).isRegularFile();
    assertThat(tempDir.resolve("build/dependency-elider.openvex.json")).isRegularFile();
    assertThat(tempDir.resolve("build/classes/META-INF/sbom/application.cdx.json")).isRegularFile();
    assertThat(tempDir.resolve("build/classes/META-INF/native-image/sbom.json")).isRegularFile();
    final ObjectMapper sbomMapper = new ObjectMapper();
    assertThat(
            sbomMapper
                .readTree(tempDir.resolve("build/baseline-sbom.cdx.json").toFile())
                .path("components")
                .toString())
        .contains("runtime-dependency", "unused-runtime");
    assertThat(
            sbomMapper
                .readTree(tempDir.resolve("build/dependency-elider-sbom.cdx.json").toFile())
                .path("components")
                .toString())
        .contains("runtime-dependency", "unused-runtime");
    assertThat(
            sbomMapper
                .readTree(tempDir.resolve("build/dependency-elider-sbom.cdx.json").toFile())
                .path("vulnerabilities")
                .get(0)
                .path("id")
                .asText())
        .isEqualTo("CVE-2026-10001");
    assertThat(original).isRegularFile();
  }

  @Test
  void multiReleaseAnalysisDeduplicatesEqualTargetAndRuntimeRelease()
      throws IOException, ReflectiveOperationException, MojoFailureException {
    final MultiReleaseFixture fixture = multiReleaseFixture("mr-equal-release");
    fixture
        .project()
        .getProperties()
        .setProperty("maven.compiler.release", Integer.toString(Runtime.version().feature()));
    final byte[] selectedRoot =
        jarEntryBytes(fixture.multiReleasePath(), "META-INF/versions/17/mrroot/Root.class");
    final ElideMojo mojo = newMojo();
    mojo.setLog(new SystemStreamLog());
    set(mojo, "project", fixture.project());
    set(mojo, "traceFiles", List.of(writeTrace("mrroot.Root\ncandidate.Keep\n").toFile()));
    set(mojo, "reportFile", tempDir.resolve("mr-equal-release-report.json").toFile());
    set(mojo, "trimJars", true);

    mojo.execute();

    assertThat(fixture.multiRelease().getFile().toPath()).isNotEqualTo(fixture.multiReleasePath());
    try (JarFile output = new JarFile(fixture.multiRelease().getFile())) {
      assertThat(jarEntryBytes(fixture.multiRelease().getFile().toPath(), "mrroot/Root.class"))
          .isEqualTo(selectedRoot);
      assertThat(output.stream().map(JarEntry::getName))
          .noneMatch(name -> name.startsWith("META-INF/versions/"));
      assertThat(output.getManifest().getMainAttributes().getValue("Multi-Release")).isNull();
    }
  }

  @Test
  void multiReleaseDefaultsToVerticalShadingAndClosesTargetAndUpperSiblingBodies()
      throws IOException, ReflectiveOperationException, MojoFailureException {
    final MultiReleaseFixture fixture = multiReleaseFixture("mr-default");
    final byte[] originalMultiReleaseBytes = Files.readAllBytes(fixture.multiReleasePath());
    final byte[] selectedTargetRoot =
        jarEntryBytes(fixture.multiReleasePath(), "META-INF/versions/11/mrroot/Root.class");
    final Path projectionDirectory = tempDir.resolve("mr-projections");
    final Path javaElevenProjection =
        MultiReleaseLibraryProjection.create(
            fixture.multiReleasePath(),
            new ArtifactCoordinate("org.example", "mr-default-root", "1.0", "jar", "", "runtime"),
            projectionDirectory,
            11);
    final Path javaSeventeenProjection =
        MultiReleaseLibraryProjection.create(
            fixture.multiReleasePath(),
            new ArtifactCoordinate("org.example", "mr-default-root", "1.0", "jar", "", "runtime"),
            projectionDirectory,
            17);
    final TrimAnalysisSession analysisSession = new TrimAnalysisSession(new DependencyJarTrimmer());
    final DependencyJarTrimmer.PreparedAnalysis javaElevenContext =
        analysisSession.prepareUnchangedPassThrough(
            javaElevenProjection,
            List.of(fixture.candidatePath()),
            new JdkApiClassPoolReader().read(Path.of(System.getProperty("java.home")), 11),
            Set.of());
    final DependencyJarTrimmer.PreparedAnalysis javaSeventeenContext =
        analysisSession.prepareUnchangedPassThrough(
            javaSeventeenProjection,
            List.of(fixture.candidatePath()),
            new JdkApiClassPoolReader().read(Path.of(System.getProperty("java.home")), 17),
            Set.of());
    final DependencyJarTrimmer.TrimAnalysis javaElevenAnalysis =
        javaElevenContext.analyze(Set.of("mrroot.Root"));
    final DependencyJarTrimmer.TrimAnalysis javaSeventeenAnalysis =
        javaSeventeenContext.analyze(Set.of("mrroot.Root"));
    assertThat(javaElevenAnalysis.reachableLibraryClasses())
        .doesNotContain("candidate/TargetSupport");
    assertThat(javaSeventeenAnalysis.reachableLibraryClasses())
        .contains("candidate/TargetSupport", "candidate/UpperSupport");
    final ElideMojo mojo = newMojo();
    mojo.setLog(new SystemStreamLog());
    set(mojo, "project", fixture.project());
    set(mojo, "traceFiles", List.of(writeTrace("mrroot.Root\ncandidate.Keep\n").toFile()));
    set(mojo, "reportFile", tempDir.resolve("mr-default-report.json").toFile());
    set(mojo, "sbomFile", tempDir.resolve("mr-default-build/sbom.json").toFile());
    set(mojo, "trimJars", true);

    mojo.execute();

    assertThat(Files.readAllBytes(fixture.multiReleasePath())).isEqualTo(originalMultiReleaseBytes);
    assertThat(fixture.multiRelease().getFile().toPath()).isNotEqualTo(fixture.multiReleasePath());
    assertThat(fixture.candidate().getFile().toPath()).isNotEqualTo(fixture.candidatePath());
    try (JarFile trimmed = new JarFile(fixture.candidate().getFile())) {
      assertThat(trimmed.getEntry("candidate/Keep.class")).isNotNull();
      assertThat(trimmed.getEntry("candidate/TargetSupport.class")).isNotNull();
      assertThat(trimmed.getEntry("candidate/TargetTail.class")).isNotNull();
      assertThat(trimmed.getEntry("candidate/UpperSupport.class")).isNotNull();
      assertThat(trimmed.getEntry("candidate/UpperTail.class")).isNotNull();
      assertThat(trimmed.getEntry("candidate/Drop.class")).isNull();
    }
    try (URLClassLoader loader =
        new URLClassLoader(
            new URL[] {
              fixture.multiRelease().getFile().toURI().toURL(),
              fixture.candidate().getFile().toURI().toURL()
            })) {
      loader.loadClass("mrroot.Root").getMethod("execute").invoke(null);
    } catch (final java.lang.reflect.InvocationTargetException exception) {
      throw new AssertionError(
          "The effective Java 17 MR method could not call candidate.UpperSupport", exception);
    } catch (final ReflectiveOperationException exception) {
      throw new AssertionError("The effective Java 17 MR method could not be invoked", exception);
    }
    final byte[] unusedUpperClass;
    try (JarFile original = new JarFile(fixture.multiReleasePath().toFile())) {
      try (InputStream input =
          original.getInputStream(
              original.getJarEntry("META-INF/versions/17/mrroot/UnusedUpperFeature.class"))) {
        unusedUpperClass = input.readAllBytes();
      }
    }
    try (JarFile trimmed = new JarFile(fixture.multiRelease().getFile())) {
      assertThat(trimmed.getManifest().getMainAttributes().getValue("Multi-Release"))
          .isEqualTo("true");
      assertThat(jarEntryBytes(trimmed, "mrroot/Root.class")).isEqualTo(selectedTargetRoot);
      assertThat(trimmed.getEntry("mrroot/VersionOnly.class")).isNull();
      assertThat(trimmed.getEntry("mrroot/RootHelper.class")).isNotNull();
      assertThat(trimmed.getEntry("mrroot/UnusedJava17.class")).isNull();
      assertThat(trimmed.getEntry("META-INF/versions/17/mrroot/VersionOnly.class")).isNotNull();
      assertThat(trimmed.getEntry("META-INF/versions/17/mrroot/UnusedUpperFeature.class"))
          .isNotNull();
      try (InputStream input =
          trimmed.getInputStream(
              trimmed.getJarEntry("META-INF/versions/17/mrroot/UnusedUpperFeature.class"))) {
        assertThat(input.readAllBytes()).isEqualTo(unusedUpperClass);
      }
      assertThat(trimmed.getEntry("META-INF/versions/11/mrroot/Root.class")).isNull();
      assertThat(trimmed.getEntry("META-INF/versions/17/mrroot/Root.class")).isNotNull();
    }
    final ObjectMapper mapper = new ObjectMapper();
    final JsonNode sbom = mapper.readTree(tempDir.resolve("mr-default-build/sbom.json").toFile());
    final JsonNode mrComponent =
        java.util.stream.StreamSupport.stream(sbom.path("components").spliterator(), false)
            .filter(component -> component.path("purl").asText().contains("mr-default-root"))
            .findFirst()
            .orElseThrow();
    assertThat(mrComponent.path("properties").findValuesAsText("name"))
        .contains(
            "elider:retainedClasses",
            "elider:totalClasses",
            "elider:mrjarStatus",
            "elider:inputPhysicalEntries",
            "elider:outputPhysicalEntries");
    assertThat(componentProperty(mrComponent, "elider:totalClasses")).isEqualTo("5");
    assertThat(componentProperty(mrComponent, "elider:retainedClasses")).isEqualTo("4");
    assertThat(componentProperty(mrComponent, "elider:mrjarStatus"))
        .isEqualTo("elevated_and_trimmed");
    assertThat(componentProperty(mrComponent, "elider:inputPhysicalEntries")).isEqualTo("8");
    assertThat(componentProperty(mrComponent, "elider:outputPhysicalEntries")).isEqualTo("6");
  }

  @Test
  void configuredPassThroughToleratesItsMissingOptionalReferenceAndKeepsLinkedCandidate()
      throws IOException, ReflectiveOperationException, MojoFailureException {
    final Path candidateWithBridgeStub =
        compileJarSources(
            "configured-pass-through-candidate-with-bridge-stub",
            Map.of(
                "Keep.java",
                "package caller; public class Keep { public static void execute() { "
                    + "bridge.Root.execute(); } }",
                "Drop.java",
                "package caller; public class Drop {}",
                "Root.java",
                "package bridge; public class Root { public static void execute() {} }"),
            null);
    final Path candidatePath =
        writeJarWithoutClass(
            "configured-pass-through-candidate.jar", candidateWithBridgeStub, "bridge/Root.class");
    final Path helperPath =
        compileJarSources(
            "configured-pass-through-helper",
            Map.of(
                "Helper.java", "package candidate; public class Helper { public void touch() {} }",
                "Entry.java", "package candidate; public class Entry {}",
                "Drop.java", "package candidate; public class Drop {}"),
            null);
    final Path rootWithOptionalStub =
        compileJarSources(
            "configured-pass-through-root",
            Map.of(
                "Root.java",
                "package bridge; public class Root { public static void execute() { "
                    + "new candidate.Helper().touch(); } "
                    + "public void optional() { "
                    + "new org.example.optional.ScriptEvaluator().run(); } }",
                "ScriptEvaluator.java",
                "package org.example.optional; public class ScriptEvaluator { "
                    + "public void run() {} }"),
            helperPath);
    final Path rootPath =
        writeJarWithoutClass(
            "configured-pass-through.jar",
            rootWithOptionalStub,
            "org/example/optional/ScriptEvaluator.class");
    final Path candidateWithOptionalStub =
        compileJarSources(
            "strict-candidate",
            Map.of(
                "Keep.java",
                "package strictcandidate; public class Keep { public static void call() { "
                    + "new org.example.optional.ScriptEvaluator().run(); } }",
                "ScriptEvaluator.java",
                "package org.example.optional; public class ScriptEvaluator { "
                    + "public void run() {} }"),
            null);
    final Path candidateWithoutOptional =
        writeJarWithoutClass(
            "strict-candidate-without-optional.jar",
            candidateWithOptionalStub,
            "org/example/optional/ScriptEvaluator.class");
    final Artifact passThrough = runtimeArtifact("explicit-pass-through", rootPath);
    final Artifact candidate = runtimeArtifact("configured-pass-through-candidate", candidatePath);
    final Artifact helper = runtimeArtifact("configured-pass-through-helper", helperPath);
    final Artifact strictCandidate = runtimeArtifact("strict-candidate", candidateWithoutOptional);
    final Set<Artifact> passThroughArtifacts =
        new LinkedHashSet<>(List.of(passThrough, candidate, helper));
    final MavenProject passThroughProject =
        projectForArtifacts("configured-pass-through", passThroughArtifacts);
    final List<String> warnings = new ArrayList<>();
    final ElideMojo passThroughMojo = newMojo();
    passThroughMojo.setLog(recordingLog(warnings));
    set(passThroughMojo, "project", passThroughProject);
    set(
        passThroughMojo,
        "traceFiles",
        List.of(writeTrace("caller.Keep\ncandidate.Entry\n").toFile()));
    set(
        passThroughMojo,
        "reportFile",
        tempDir.resolve("configured-pass-through-report.json").toFile());
    set(
        passThroughMojo,
        "sbomFile",
        tempDir.resolve("configured-pass-through-build/sbom.json").toFile());
    set(passThroughMojo, "trimJars", true);
    set(
        passThroughMojo,
        "excludedArtifacts",
        List.of("org.example:configured-pass-through-helper"));
    set(
        passThroughMojo,
        "trimSkipArtifacts",
        List.of("org.example:explicit-pass-through:1.0:jar:"));
    final byte[] originalPassThroughBytes = Files.readAllBytes(rootPath);

    passThroughMojo.execute();

    assertThat(passThrough.getFile().toPath()).isEqualTo(rootPath);
    assertThat(Files.readAllBytes(rootPath)).isEqualTo(originalPassThroughBytes);
    assertThat(warnings)
        .anySatisfy(
            warning ->
                assertThat(warning)
                    .contains("configured dependency unchanged")
                    .contains("external links from unchanged classes are tolerated")
                    .contains("org.example:explicit-pass-through:jar:1.0"));
    assertThat(passThroughProject.getArtifacts())
        .extracting(Artifact::getArtifactId)
        .contains("explicit-pass-through", "configured-pass-through-helper");
    assertThat(candidate.getFile().toPath()).isNotEqualTo(candidatePath);
    assertThat(helper.getFile().toPath()).isNotEqualTo(helperPath);
    try (JarFile trimmed = new JarFile(candidate.getFile())) {
      assertThat(trimmed.getEntry("caller/Keep.class")).isNotNull();
      assertThat(trimmed.getEntry("caller/Drop.class")).isNull();
    }
    try (JarFile trimmed = new JarFile(helper.getFile())) {
      assertThat(trimmed.getEntry("candidate/Helper.class")).isNotNull();
      assertThat(trimmed.getEntry("candidate/Drop.class")).isNull();
    }
    try (URLClassLoader loader =
        new URLClassLoader(
            new URL[] {
              candidate.getFile().toURI().toURL(),
              passThrough.getFile().toURI().toURL(),
              helper.getFile().toURI().toURL()
            })) {
      loader.loadClass("caller.Keep").getMethod("execute").invoke(null);
    } catch (final ReflectiveOperationException exception) {
      throw new AssertionError("The candidate to pass-through to helper chain failed", exception);
    }

    final Set<Artifact> strictArtifacts = new LinkedHashSet<>(List.of(strictCandidate));
    final MavenProject strictProject = projectForArtifacts("strict-candidate", strictArtifacts);
    final ElideMojo strictMojo = newMojo();
    strictMojo.setLog(new SystemStreamLog());
    set(strictMojo, "project", strictProject);
    set(strictMojo, "traceFiles", List.of(writeTrace("strictcandidate.Keep\n").toFile()));
    set(strictMojo, "reportFile", tempDir.resolve("strict-candidate-report.json").toFile());
    set(strictMojo, "trimJars", true);
    assertThatThrownBy(strictMojo::execute)
        .isInstanceOf(MojoFailureException.class)
        .hasMessageContaining("unresolved references")
        .hasMessageContaining("org/example/optional/ScriptEvaluator");
    assertThat(strictCandidate.getFile().toPath()).isEqualTo(candidateWithoutOptional);
  }

  @Test
  void analyzeServiceDirectFinishStagesVerticalShadingOutput()
      throws IOException, MojoFailureException {
    final MultiReleaseFixture fixture = multiReleaseFixture("mr-direct-finish");
    final MavenElisionService.Analysis analysis =
        new MavenElisionService()
            .analyze(
                fixture.project(),
                new MavenElisionService.AnalysisOptions(
                    List.of(writeTrace("mrroot.Root\ncandidate.Keep\n").toFile()),
                    List.of(),
                    null,
                    null,
                    false,
                    true,
                    List.of(),
                    false,
                    List.of(),
                    false,
                    true,
                    true,
                    "vertical-shading"));

    final ArtifactTrimRecord record =
        analysis.trimRecords().stream()
            .filter(item -> "mr-direct-finish-root".equals(item.coordinate().artifactId()))
            .findFirst()
            .orElseThrow();
    assertThat(record.mrjarStatus()).isEqualTo("elevated_and_trimmed");
    assertThat(record.trimmedPath()).isRegularFile();
    try (JarFile output = new JarFile(record.trimmedPath().toFile())) {
      assertThat(output.getEntry("mrroot/Root.class")).isNotNull();
      assertThat(output.getEntry("mrroot/RootHelper.class")).isNotNull();
      assertThat(output.getEntry("META-INF/versions/11/mrroot/Root.class")).isNull();
    }
  }

  @Test
  void elevatedServicesDropProvidersMissingAtTargetButKeepUnknownProviders()
      throws IOException, ReflectiveOperationException, MojoFailureException {
    final Path rootBase =
        compileJarSources(
            "mr-service-base",
            Map.of(
                "Root.java", "package mrservice; public class Root { public static void run() {} }",
                "Spi.java", "package mrservice; public interface Spi {}"),
            null,
            8);
    final Path targetRoot =
        compileJarSources(
            "mr-service-target",
            Map.of(
                "Root.java",
                "package mrservice; public class Root { public static void run() {} }"),
            rootBase,
            11);
    final Path upperClasses =
        compileJarSources(
            "mr-service-upper",
            Map.of(
                "Provider.java",
                "package mrservice; class Provider implements Spi { public Provider() {} }"),
            rootBase,
            17);
    final Path droppedProviderPath =
        compileJarSources(
            "mr-service-dropped-provider",
            Map.of(
                "Provider.java",
                "package droppedprovider; public class Provider implements mrservice.Spi { "
                    + "public Provider() {} }",
                "Keep.java",
                "package droppedprovider; public class Keep {}"),
            rootBase,
            8);
    final Path multiReleasePath =
        writeMultiReleaseJar(
            "mr-service-root.jar",
            rootBase,
            null,
            targetRoot,
            upperClasses,
            Map.of(
                "META-INF/services/mrservice.Spi",
                "mrservice.Provider\n" + "droppedprovider.Provider\n" + "external.Provider\n"));
    final Artifact root = runtimeArtifact("mr-service-root", multiReleasePath);
    final Artifact droppedProvider =
        runtimeArtifact("mr-service-dropped-provider", droppedProviderPath);
    final ArtifactCoordinate droppedProviderCoordinate =
        new ArtifactCoordinate(
            "org.example", "mr-service-dropped-provider", "1.0", "jar", "", "runtime");
    final MavenProject project =
        projectForArtifacts(
            "mr-service-consumer", new LinkedHashSet<>(List.of(root, droppedProvider)));
    project.getProperties().setProperty("maven.compiler.release", "11");
    final MavenElisionService service = new MavenElisionService();
    final Path trace = writeTrace("mrservice.Root\n");
    final MavenElisionService.PreparedAnalysis prepared =
        service.prepare(
            project,
            new MavenElisionService.AnalysisOptions(
                List.of(trace.toFile()),
                List.of(),
                null,
                null,
                false,
                true,
                List.of("droppedprovider.Keep"),
                false,
                List.of(),
                false,
                true,
                false,
                "vertical-shading"));
    assertThat(prepared.rawDecision().retainedArtifacts()).contains(droppedProviderCoordinate);
    final MavenElisionService.EffectiveAnalysis effective = service.finishAnalysis(prepared);
    assertThat(effective.effectiveDecision().retainedArtifacts())
        .contains(droppedProviderCoordinate);
    assertThat(effective.trimAnalysis().candidateAnalyses()).containsKey(droppedProviderCoordinate);
    assertThat(
            effective
                .trimAnalysis()
                .candidateAnalyses()
                .get(droppedProviderCoordinate)
                .retainedClasses())
        .contains("droppedprovider/Keep")
        .doesNotContain("droppedprovider/Provider");
    final MavenDependencyTrimmer.TrimResult result =
        MavenDependencyTrimmer.trimEffectiveOutputs(effective);
    final ArtifactTrimRecord rootRecord =
        result.records().stream()
            .filter(record -> "mr-service-root".equals(record.coordinate().artifactId()))
            .findFirst()
            .orElseThrow();
    final ArtifactTrimRecord providerRecord =
        result.records().stream()
            .filter(
                record -> "mr-service-dropped-provider".equals(record.coordinate().artifactId()))
            .findFirst()
            .orElseThrow();

    try (JarFile providerOutput = new JarFile(providerRecord.trimmedPath().toFile())) {
      assertThat(providerOutput.getEntry("droppedprovider/Keep.class")).isNotNull();
      assertThat(providerOutput.getEntry("droppedprovider/Provider.class")).isNull();
    }

    try (JarFile output = new JarFile(rootRecord.trimmedPath().toFile())) {
      assertThat(output.getEntry("META-INF/versions/17/mrservice/Provider.class")).isNotNull();
      final JarEntry descriptor = output.getJarEntry("META-INF/services/mrservice.Spi");
      assertThat(descriptor).isNotNull();
      try (InputStream input = output.getInputStream(descriptor)) {
        final String providers =
            new String(input.readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
        assertThat(providers)
            .doesNotContain("mrservice.Provider", "droppedprovider.Provider")
            .contains("external.Provider");
      }
    }
  }

  @Test
  void promotedArtifactSecondPassAcceptsVersionOnlyLogicalRoot()
      throws IOException, MojoFailureException {
    final MultiReleaseFixture fixture = multiReleaseFixture("mr-promotion");
    final Path trace = writeTrace("mrroot.Root\nmrroot.VersionOnly\n");
    final MavenElisionService service = new MavenElisionService();
    final MavenElisionService.PreparedAnalysis prepared =
        service.prepare(
            fixture.project(),
            new MavenElisionService.AnalysisOptions(
                List.of(trace.toFile()),
                List.of(),
                null,
                null,
                false,
                true,
                List.of(),
                false,
                List.of(),
                false,
                true,
                true,
                "vertical-shading"));
    final ArtifactCoordinate mrCoordinate =
        new ArtifactCoordinate("org.example", "mr-promotion-root", "1.0", "jar", "", "runtime");
    final ArtifactCoordinate candidateCoordinate =
        new ArtifactCoordinate(
            "org.example", "mr-promotion-candidate", "1.0", "jar", "", "runtime");
    assertThat(prepared.rawDecision().elidedArtifacts()).contains(candidateCoordinate);
    final MavenDependencyTrimmer.TrimRequest initialRequest =
        tieredRequest(prepared, prepared.rawDecision().retainedArtifacts());
    final MavenDependencyTrimmer.InMemoryAnalysis first =
        MavenDependencyTrimmer.analyzeInMemory(initialRequest, Map.of(), Set.of());
    assertThat(first.reachableArtifacts()).contains(candidateCoordinate);
    assertThat(first.candidateRoots().get(mrCoordinate)).contains("mrroot.VersionOnly");
    final Path mrPath = fixture.multiReleasePath().toAbsolutePath().normalize();
    final MavenDependencyTrimmer.ArtifactRootKey rootKey =
        new MavenDependencyTrimmer.ArtifactRootKey(
            mrCoordinate, mrPath, ArtifactDigests.read(mrPath).sha256());
    final Set<ArtifactCoordinate> promotedCoordinates =
        union(prepared.rawDecision().retainedArtifacts(), candidateCoordinate);
    final Map<MavenDependencyTrimmer.ArtifactRootKey, Set<String>> discoveredRoots =
        Map.of(rootKey, first.candidateRoots().get(mrCoordinate));
    final MavenDependencyTrimmer.InMemoryAnalysis second =
        MavenDependencyTrimmer.analyzeInMemory(
            tieredRequest(prepared, promotedCoordinates),
            discoveredRoots,
            Set.of(candidateCoordinate));

    assertThat(second.candidateRoots().get(mrCoordinate)).contains("mrroot.VersionOnly");
    assertThat(second.candidateRoots().get(mrCoordinate))
        .noneMatch(name -> name.startsWith("META-INF.versions."));
    final MavenDependencyTrimmer.InMemoryAnalysis skippedMultiRelease =
        MavenDependencyTrimmer.analyzeInMemory(
            tieredRequest(prepared, promotedCoordinates), discoveredRoots, Set.of(mrCoordinate));
    assertThat(skippedMultiRelease.candidateAnalyses()).containsKey(candidateCoordinate);
    assertThat(skippedMultiRelease.candidateRoots().get(candidateCoordinate))
        .contains("candidate.TargetSupport", "candidate.UpperSupport");
    assertThat(skippedMultiRelease.candidateRoots()).doesNotContainKey(mrCoordinate);
  }

  @Test
  void explicitPassThroughKeepsMultiReleaseJarByteIdentical()
      throws IOException, ReflectiveOperationException, MojoFailureException {
    final MultiReleaseFixture fixture = multiReleaseFixture("mr-pass-through", true);
    final byte[] original = Files.readAllBytes(fixture.multiReleasePath());
    final ElideMojo mojo = newMojo();
    mojo.setLog(new SystemStreamLog());
    set(mojo, "project", fixture.project());
    set(mojo, "traceFiles", List.of(writeTrace("mrroot.Root\ncandidate.Keep\n").toFile()));
    set(mojo, "reportFile", tempDir.resolve("mr-pass-through-report.json").toFile());
    set(mojo, "trimJars", true);
    set(mojo, "mrjarStrategy", "pass-through");

    mojo.execute();

    assertThat(fixture.multiRelease().getFile().toPath()).isEqualTo(fixture.multiReleasePath());
    assertThat(Files.readAllBytes(fixture.multiReleasePath())).isEqualTo(original);
    assertThat(fixture.candidate().getFile().toPath()).isNotEqualTo(fixture.candidatePath());
    try (JarFile candidate = new JarFile(fixture.candidate().getFile())) {
      assertThat(candidate.getEntry("candidate/TargetSupport.class")).isNotNull();
      assertThat(candidate.getEntry("candidate/TargetTail.class")).isNotNull();
    }
    final Path targetView =
        MultiReleaseLibraryProjection.create(
            fixture.multiReleasePath(),
            new ArtifactCoordinate(
                "org.example", "mr-pass-through-root", "1.0", "jar", "", "runtime"),
            tempDir.resolve("mr-pass-through-projection"),
            11);
    try (URLClassLoader loader =
        new URLClassLoader(
            new URL[] {
              targetView.toUri().toURL(), fixture.candidate().getFile().toURI().toURL()
            })) {
      loader.loadClass("mrroot.Root").getMethod("execute").invoke(null);
    } catch (final java.lang.reflect.InvocationTargetException exception) {
      throw new AssertionError(
          "The Java 11 MR view could not call its retained sibling implementation", exception);
    } catch (final ReflectiveOperationException exception) {
      throw new AssertionError("The Java 11 MR view could not be invoked", exception);
    }
  }

  @Test
  void mrjarStrategyPassThroughKeepsSpringOptionalLinksSafe()
      throws IOException, ReflectiveOperationException, MojoFailureException {
    final SpringOptionalMrjarInput input = springOptionalMrjarInput("spring-optional");
    final Artifact springAop = runtimeArtifact("spring-aop", input.springAopPath());
    final Artifact springCore = runtimeArtifact("spring-core", input.springCorePath());
    final Artifact candidate = runtimeArtifact("optional-link-candidate", input.candidatePath());
    final Set<Artifact> artifacts = new LinkedHashSet<>(List.of(springAop, springCore, candidate));
    final MavenProject project = projectForArtifacts("spring-optional-link", artifacts);
    project.getProperties().setProperty("maven.compiler.release", "11");
    final List<java.io.File> trace =
        List.of(writeTrace("org.springframework.aop.AopRoot\ncandidate.Entry\n").toFile());
    final List<String> configuredPassThrough = List.of("org.example:spring-aop:1.0:jar:");
    final byte[] originalSpringAop = Files.readAllBytes(input.springAopPath());
    final byte[] originalSpringCore = Files.readAllBytes(input.springCorePath());

    final ElideMojo verticalShadingMojo = newMojo();
    verticalShadingMojo.setLog(new SystemStreamLog());
    set(verticalShadingMojo, "project", project);
    set(verticalShadingMojo, "traceFiles", trace);
    set(verticalShadingMojo, "reportFile", tempDir.resolve("spring-default-report.json").toFile());
    set(verticalShadingMojo, "trimJars", true);
    set(verticalShadingMojo, "trimSkipArtifacts", configuredPassThrough);

    assertThatThrownBy(verticalShadingMojo::execute)
        .isInstanceOf(MojoFailureException.class)
        .hasMessageContaining("unresolved references")
        .hasMessageContaining("kotlin/coroutines/Continuation");
    assertThat(springAop.getFile().toPath()).isEqualTo(input.springAopPath());
    assertThat(springCore.getFile().toPath()).isEqualTo(input.springCorePath());
    assertThat(candidate.getFile().toPath()).isEqualTo(input.candidatePath());

    final ElideMojo passThroughMojo = newMojo();
    passThroughMojo.setLog(new SystemStreamLog());
    set(passThroughMojo, "project", project);
    set(passThroughMojo, "traceFiles", trace);
    set(passThroughMojo, "reportFile", tempDir.resolve("spring-pass-through-report.json").toFile());
    set(passThroughMojo, "trimJars", true);
    set(passThroughMojo, "mrjarStrategy", "pass-through");
    set(passThroughMojo, "trimSkipArtifacts", configuredPassThrough);

    passThroughMojo.execute();

    assertThat(springAop.getFile().toPath()).isEqualTo(input.springAopPath());
    assertThat(Files.readAllBytes(input.springAopPath())).isEqualTo(originalSpringAop);
    assertThat(springCore.getFile().toPath()).isEqualTo(input.springCorePath());
    assertThat(Files.readAllBytes(input.springCorePath())).isEqualTo(originalSpringCore);
    assertThat(candidate.getFile().toPath()).isNotEqualTo(input.candidatePath());
    try (JarFile trimmed = new JarFile(candidate.getFile())) {
      assertThat(trimmed.getEntry("candidate/Keep.class")).isNotNull();
      assertThat(trimmed.getEntry("candidate/Drop.class")).isNull();
    }
  }

  @Test
  void disabledTrimmingKeepsRuntimeProjectionWhenCompilerReleaseExceedsRuntime()
      throws IOException, ReflectiveOperationException, MojoFailureException {
    final MultiReleaseFixture fixture = multiReleaseFixture("mr-no-trim");
    final byte[] original = Files.readAllBytes(fixture.multiReleasePath());
    fixture.project().getProperties().setProperty("maven.compiler.release", "25");
    final ElideMojo mojo = newMojo();
    mojo.setLog(new SystemStreamLog());
    set(mojo, "project", fixture.project());
    set(mojo, "traceFiles", List.of(writeTrace("mrroot.Root\ncandidate.Keep\n").toFile()));
    set(mojo, "reportFile", tempDir.resolve("mr-no-trim-report.json").toFile());
    set(mojo, "trimJars", false);

    mojo.execute();

    assertThat(fixture.multiRelease().getFile().toPath()).isEqualTo(fixture.multiReleasePath());
    assertThat(Files.readAllBytes(fixture.multiReleasePath())).isEqualTo(original);
    assertThat(fixture.candidate().getFile().toPath()).isEqualTo(fixture.candidatePath());
  }

  private MavenElisionService.Analysis analyzeTrim(
      final MavenProject project, final String traceClasses)
      throws IOException, MojoFailureException {
    return new MavenElisionService()
        .analyze(
            project,
            List.of(writeTrace(traceClasses).toFile()),
            List.of(),
            null,
            null,
            false,
            true,
            List.of());
  }

  @Test
  void testScopeMultiReleaseJarIsLeftUntouchedDuringProductionTrimming()
      throws IOException, ReflectiveOperationException, MojoFailureException {
    final Artifact runtime = compiledArtifact();
    final Artifact directRuntime =
        runtimeArtifact("runtime-dependency", runtime.getFile().toPath());
    final Path versionedClassJar =
        compileJarSources(
            "test-scope-variant",
            Map.of("testscope/Variant.java", "package testscope; public final class Variant {}"),
            null);
    final Path testJar = tempDir.resolve("test-scope-mr.jar");
    try (JarFile compiled = new JarFile(versionedClassJar.toFile());
        ZipOutputStream output = new ZipOutputStream(Files.newOutputStream(testJar))) {
      output.putNextEntry(new ZipEntry("META-INF/MANIFEST.MF"));
      output.write(
          "Manifest-Version: 1.0\r\nMulti-Release: true\r\n\r\n"
              .getBytes(java.nio.charset.StandardCharsets.UTF_8));
      output.closeEntry();
      output.putNextEntry(new ZipEntry("META-INF/versions/11/testscope/Variant.class"));
      try (InputStream input =
          compiled.getInputStream(compiled.getEntry("testscope/Variant.class"))) {
        input.transferTo(output);
      }
      output.closeEntry();
    }
    final Artifact testOnly =
        new DefaultArtifact(
            "org.example",
            "test-only-mr",
            "1.0",
            "test",
            "jar",
            null,
            new DefaultArtifactHandler("jar"));
    testOnly.setFile(testJar.toFile());
    final MavenProject project =
        project(runtime, new LinkedHashSet<>(List.of(directRuntime, testOnly)), testOnly);
    project.setGroupId("org.example");
    project.setArtifactId("consumer");
    project.setVersion("1.0");
    project.getProperties().setProperty("maven.compiler.release", "21");
    final Build build = new Build();
    build.setDirectory(tempDir.resolve("scope-build").toString());
    project.setBuild(build);
    final ElideMojo mojo = newMojo();
    mojo.setLog(new SystemStreamLog());
    set(mojo, "project", project);
    set(mojo, "traceFiles", List.of(writeTrace("sample.Keep\n").toFile()));
    set(mojo, "reportFile", tempDir.resolve("scope-report.json").toFile());
    set(mojo, "trimJars", true);
    set(mojo, "sbomFile", tempDir.resolve("scope-build/sbom.json").toFile());

    mojo.execute();

    assertThat(runtime.getFile().toPath()).isNotEqualTo(tempDir.resolve("runtime-dependency.jar"));
    assertThat(testOnly.getFile().toPath()).isEqualTo(testJar);
    assertThat(project.getArtifacts()).contains(testOnly);
    assertThat(project.getDependencyArtifacts()).contains(testOnly);
    try (JarFile unchanged = new JarFile(testOnly.getFile())) {
      assertThat(unchanged.getEntry("META-INF/versions/11/testscope/Variant.class")).isNotNull();
    }
  }

  private Path compileDynamicRootJar() throws IOException {
    return compileJarSources(
        "End",
        Map.ofEntries(
            Map.entry("End.java", "package chain; public interface End { static void touch() {} }"),
            Map.entry("Provider.java", "package chain; public class Provider implements End {}"),
            Map.entry("Reflected.java", "package chain; public class Reflected {}"),
            Map.entry("ProxyMarker.java", "package chain; public interface ProxyMarker {}"),
            Map.entry("SpringAuto.java", "package chain; public class SpringAuto {}"),
            Map.entry("Factory.java", "package chain; public class Factory {}"),
            Map.entry("MetadataCondition.java", "package chain; public class MetadataCondition {}"),
            Map.entry("NativeImageRoot.java", "package chain; public class NativeImageRoot {}"),
            Map.entry(
                "NativeImageJniRoot.java", "package chain; public class NativeImageJniRoot {}"),
            Map.entry("NativeImageBundle.java", "package chain; public class NativeImageBundle {}"),
            Map.entry(
                "NativeImageBundleCondition.java",
                "package chain; public class NativeImageBundleCondition {}"),
            Map.entry(
                "NativeImageFeature.java", "package chain; public class NativeImageFeature {}"),
            Map.entry(
                "NativeImageBuildTime.java", "package chain; public class NativeImageBuildTime {}"),
            Map.entry(
                "AutoConfiguration.java",
                "package org.springframework.boot.autoconfigure; public class "
                    + "AutoConfiguration { public static class Nested {} }"),
            Map.entry(
                "ConditionalOnCheckpointRestore.java",
                "package org.springframework.boot.autoconfigure.condition; public class "
                    + "ConditionalOnCheckpointRestore {}"),
            Map.entry("Resource.java", "package org.crac; public interface Resource {}"),
            Map.entry(
                "KafkaStreamsAnnotationDrivenConfiguration.java",
                "package org.springframework.boot.autoconfigure.kafka; public class "
                    + "KafkaStreamsAnnotationDrivenConfiguration {}"),
            Map.entry(
                "TaskSchedulingConfigurations.java",
                "package org.springframework.boot.autoconfigure.task; public class "
                    + "TaskSchedulingConfigurations { public static class "
                    + "TaskSchedulerConfiguration {} }"),
            Map.entry("BeforeAuto.java", "package chain; public class BeforeAuto {}"),
            Map.entry("AfterAuto.java", "package chain; public class AfterAuto {}"),
            Map.entry("Unused.java", "package chain; public class Unused {}")),
        null);
  }

  @Test
  void trimRootsPropagateAcrossRetainedSiblingJars()
      throws IOException, ReflectiveOperationException, MojoFailureException {
    final Path cjar = compileDynamicRootJar();
    final Path bjar =
        compileJar(
            "Bridge",
            "package chain; public class Bridge { public void next() { new Helper().touch(); "
                + "End.touch(); } private static class Helper { void touch() {} } }",
            cjar);
    final Path compiledRoot =
        compileJar(
            "Root",
            "package chain; public class Root { public Bridge next() { return null; } }",
            bjar);
    final Path ajar =
        rewriteJar(
            compiledRoot,
            Map.of(
                "META-INF/native-image/test/reflect-config.json",
                "[{\"name\":\"chain.Reflected\"}]",
                "META-INF/native-image/test/proxy-config.json",
                "[[\"chain.ProxyMarker\"]]",
                "META-INF/native-image/test/tomcat-style/native-image.properties",
                "Args = -H:ReflectionConfigurationResources=${.}/tomcat-reflection.json "
                    + "-H:ResourceConfigurationResources=${.}/tomcat-resource.json\n",
                "META-INF/native-image/test/tomcat-style/tomcat-reflection.json",
                "[{\"name\":\"chain.NativeImageRoot\"}]",
                "META-INF/native-image/test/tomcat-style/tomcat-jni.json",
                "[{\"name\":\"chain.NativeImageJniRoot\"}]",
                "META-INF/native-image/test/tomcat-style/tomcat-resource.json",
                "{\"resources\":[{\"pattern\":\".*\"}],"
                    + "\"bundles\":[{\"name\":\"chain.NativeImageBundle\","
                    + "\"condition\":{\"typeReached\":\"chain.NativeImageBundleCondition\"}}]}",
                "META-INF/native-image/test/spring-web/native-image.properties",
                "Args = --enable-http --enable-https\n",
                "META-INF/native-image/test/spring-core/native-image.properties",
                "Args = --initialize-at-build-time=chain.NativeImageBuildTime \\\n"
                    + "  --features=chain.NativeImageFeature\n",
                "META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports",
                "chain.SpringAuto\n",
                "META-INF/spring.factories",
                "org.example.Factory=chain.Factory\n"));
    final Path metadatfirstJar =
        rewriteJar(
            cjar,
            Map.of(
                "META-INF/spring-autoconfigure-metadata.properties",
                "chain.SpringAuto.ConditionalOnClass=chain.MetadataCondition\n"
                    + "org.springframework.boot.autoconfigure.AutoConfiguration=\n"
                    + "org.springframework.boot.autoconfigure.AutoConfiguration$Nested=\n"
                    + "org.springframework.boot.autoconfigure.condition."
                    + "ConditionalOnCheckpointRestore."
                    + "ConditionalOnClass=org.crac.Resource\n"
                    + "org.springframework.boot.autoconfigure.kafka."
                    + "KafkaStreamsAnnotationDrivenConfiguration.ConditionalOnBean=\n"
                    + "org.springframework.boot.autoconfigure.kafka."
                    + "KafkaStreamsAnnotationDrivenConfiguration."
                    + "ConditionalOnWebApplication=SERVLET\n"
                    + "org.springframework.boot.autoconfigure.task.TaskSchedulingConfigurations$"
                    + "TaskSchedulerConfiguration.ConditionalOnBean=\n"
                    + "org.springframework.boot.autoconfigure.task.TaskSchedulingConfigurations$"
                    + "TaskSchedulerConfiguration.ConditionalOnWebApplication=\n"
                    + "org.springframework.boot.autoconfigure.condition."
                    + "ConditionalOnCheckpointRestore=\n"
                    + "chain.SpringAuto.AutoConfigureBefore=chain.BeforeAuto\n"
                    + "chain.SpringAuto.AutoConfigureAfter=chain.AfterAuto\n"
                    + "chain.SpringAuto.AutoConfigureOrder=10\n"));
    final Path serviceJar =
        descriptorJar("service-owner.jar", "META-INF/services/chain.End", "chain.Provider\n");
    final Artifact a = runtimeArtifact("chain-a", ajar);
    final Artifact b = runtimeArtifact("chain-b", bjar);
    final Artifact c = runtimeArtifact("chain-c", metadatfirstJar);
    final Artifact serviceOwner = runtimeArtifact("service-owner", serviceJar);
    final Set<Artifact> artifacts = new LinkedHashSet<>(List.of(a, b, c, serviceOwner));
    final MavenProject project = newProject();
    project.setArtifacts(artifacts);
    project.setDependencyArtifacts(new LinkedHashSet<>(artifacts));
    project.setGroupId("org.example");
    project.setArtifactId("chain-consumer");
    project.setVersion("1.0");
    project.setName("Chain Consumer");
    project.getProperties().setProperty("maven.compiler.release", "21");
    final Build build = new Build();
    build.setDirectory(tempDir.resolve("chain-build").toString());
    project.setBuild(build);
    final ElideMojo mojo = newMojo();
    mojo.setLog(new SystemStreamLog());
    set(mojo, "project", project);
    set(mojo, "traceFiles", List.of(writeTrace("chain.Root\n").toFile()));
    set(mojo, "excludedArtifacts", List.of("org.example:chain-b", "org.example:chain-c"));
    set(mojo, "reportFile", tempDir.resolve("chain-report.json").toFile());
    set(mojo, "sbomFile", tempDir.resolve("chain-build/chain-sbom.json").toFile());
    set(mojo, "trimJars", true);

    mojo.execute();

    assertClassMetadataRootsRetained(c);
    assertJarContains(a, "chain/Root.class");
    assertJarContains(b, "chain/Bridge.class");
    assertJarContains(b, "chain/Bridge$Helper.class");
    assertJarContains(c, "chain/End.class");
    assertJarContains(c, "chain/Provider.class");
    assertThat(serviceOwner.getFile().toPath()).isEqualTo(serviceJar);
    assertThat(project.getArtifacts()).contains(serviceOwner);
    try (JarFile trimmed = new JarFile(c.getFile())) {
      assertThat(trimmed.getEntry("chain/Unused.class")).isNull();
    }
  }

  @Test
  void trimRootsPropagateAcrossCyclicArtifactReferences()
      throws IOException, ReflectiveOperationException, MojoFailureException {
    final Path compiled =
        compileJarSources(
            "cycle-all",
            Map.of(
                "cycle/Root.java", "package cycle; public class Root { public Bridge bridge; }",
                "cycle/Bridge.java", "package cycle; public class Bridge { public End end; }",
                "cycle/End.java", "package cycle; public class End { public Root root; }",
                "cycle/BaselineB.java", "package cycle; public class BaselineB {}",
                "cycle/BaselineC.java", "package cycle; public class BaselineC {}",
                "cycle/UnusedA.java", "package cycle; public class UnusedA {}",
                "cycle/UnusedB.java", "package cycle; public class UnusedB {}",
                "cycle/UnusedC.java", "package cycle; public class UnusedC {}"),
            null);
    final Path firstJar =
        selectJarEntries(
            compiled, "cycle-a.jar", Set.of("cycle/Root.class", "cycle/UnusedA.class"));
    final Path secondJar =
        selectJarEntries(
            compiled,
            "cycle-b.jar",
            Set.of("cycle/Bridge.class", "cycle/BaselineB.class", "cycle/UnusedB.class"));
    final Path thirdJar =
        selectJarEntries(
            compiled,
            "cycle-c.jar",
            Set.of("cycle/End.class", "cycle/BaselineC.class", "cycle/UnusedC.class"));
    final Artifact a = runtimeArtifact("cycle-a", firstJar);
    final Artifact b = runtimeArtifact("cycle-b", secondJar);
    final Artifact c = runtimeArtifact("cycle-c", thirdJar);
    final Set<Artifact> artifacts = new LinkedHashSet<>(List.of(a, b, c));
    final MavenProject project = newProject();
    project.setArtifacts(artifacts);
    project.setDependencyArtifacts(new LinkedHashSet<>(artifacts));
    project.setGroupId("org.example");
    project.setArtifactId("cycle-consumer");
    project.setVersion("1.0");
    project.setName("Cyclic Consumer");
    project.getProperties().setProperty("maven.compiler.release", "21");
    final Path productionSources = tempDir.resolve("cycle-sources");
    Files.createDirectories(productionSources);
    Files.writeString(productionSources.resolve("Seed.java"), "class Seed {}\n");
    project.addCompileSourceRoot(productionSources.toString());
    final Build build = new Build();
    build.setDirectory(tempDir.resolve("cycle-build").toString());
    project.setBuild(build);
    final ElideMojo mojo = newMojo();
    mojo.setLog(new SystemStreamLog());
    set(mojo, "project", project);
    set(mojo, "traceFiles", List.of(writeTrace("cycle.Root\n").toFile()));
    set(mojo, "excludedArtifacts", List.of("org.example:cycle-b", "org.example:cycle-c"));
    set(mojo, "reportFile", tempDir.resolve("cycle-report.json").toFile());
    set(mojo, "sbomFile", tempDir.resolve("cycle-build/cycle-sbom.json").toFile());
    set(mojo, "trimJars", true);
    set(mojo, "sourceRootsComplete", true);
    set(mojo, "trimRoots", List.of("cycle.BaselineB", "cycle.BaselineC"));

    mojo.execute();

    assertJarEntryPresent(a, "cycle/Root.class");
    assertJarEntryPresent(b, "cycle/Bridge.class");
    assertJarEntryPresent(c, "cycle/End.class");
    assertJarOmits(a, "cycle/UnusedA.class");
    assertJarOmits(b, "cycle/UnusedB.class");
    assertJarOmits(c, "cycle/UnusedC.class");
  }

  private void assertClassMetadataRootsRetained(final Artifact artifact) throws IOException {
    assertJarContains(artifact, "chain/Reflected.class");
    assertJarContains(artifact, "chain/ProxyMarker.class");
    assertJarContains(artifact, "chain/SpringAuto.class");
    assertJarContains(artifact, "chain/Factory.class");
    assertJarContains(artifact, "chain/MetadataCondition.class");
    assertJarContains(artifact, "chain/NativeImageRoot.class");
    assertJarContains(artifact, "chain/NativeImageJniRoot.class");
    assertJarContains(artifact, "chain/NativeImageBundle.class");
    assertJarContains(artifact, "chain/NativeImageBundleCondition.class");
    assertJarContains(artifact, "chain/NativeImageBuildTime.class");
    assertJarContains(artifact, "chain/NativeImageFeature.class");
    assertJarContains(artifact, "org/springframework/boot/autoconfigure/AutoConfiguration.class");
    assertJarContains(
        artifact, "org/springframework/boot/autoconfigure/AutoConfiguration$Nested.class");
    assertJarContains(
        artifact,
        "org/springframework/boot/autoconfigure/condition/ConditionalOnCheckpointRestore.class");
    assertJarContains(
        artifact,
        "org/springframework/boot/autoconfigure/kafka/"
            + "KafkaStreamsAnnotationDrivenConfiguration.class");
    assertJarContains(
        artifact, "org/springframework/boot/autoconfigure/task/TaskSchedulingConfigurations.class");
    assertJarContains(
        artifact,
        "org/springframework/boot/autoconfigure/task/TaskSchedulingConfigurations$"
            + "TaskSchedulerConfiguration.class");
    assertJarContains(artifact, "org/crac/Resource.class");
    assertJarContains(artifact, "chain/BeforeAuto.class");
    assertJarContains(artifact, "chain/AfterAuto.class");
  }

  @Test
  void rootModuleInfoPassThroughRetainsAndExecutesHelperFromTrimmedSibling()
      throws IOException, ReflectiveOperationException, MojoFailureException {
    final Path candidateJar =
        compileJarSources(
            "module-pass-through-candidate",
            Map.of(
                "Entry.java",
                "package candidate; public class Entry {}",
                "Helper.java",
                "package candidate; public class Helper { public static String value() { "
                    + "return \"ok\"; } }",
                "Drop.java",
                "package candidate; public class Drop {}"),
            null);
    final Path compiledPassThrough =
        compileJarSources(
            "module-pass-through-root",
            Map.of(
                "Root.java",
                "package pass; public class Root { public static String call() { "
                    + "return candidate.Helper.value(); } }"),
            candidateJar);
    final Path passThroughJar =
        addRootModuleDescriptor(compiledPassThrough, "pass.through", "pass");
    final Artifact passThrough = runtimeArtifact("module-pass-through", passThroughJar);
    final Artifact candidate = runtimeArtifact("module-candidate", candidateJar);
    final MavenProject project =
        projectForArtifacts(
            "module-pass-through", new LinkedHashSet<>(List.of(passThrough, candidate)));
    final byte[] originalBytes = Files.readAllBytes(passThroughJar);
    final List<String> warnings = new ArrayList<>();
    final ElideMojo mojo = newMojo();
    mojo.setLog(recordingLog(warnings));
    set(mojo, "project", project);
    set(mojo, "traceFiles", List.of(writeTrace("candidate.Entry\npass.Root\n").toFile()));
    set(mojo, "reportFile", tempDir.resolve("module-pass-through-report.json").toFile());
    set(mojo, "sbomFile", tempDir.resolve("module-pass-through-build/sbom.json").toFile());
    set(mojo, "trimJars", true);

    mojo.execute();

    assertThat(passThrough.getFile().toPath()).isEqualTo(passThroughJar);
    assertThat(Files.readAllBytes(passThroughJar)).isEqualTo(originalBytes);
    assertThat(project.getArtifacts()).contains(passThrough, candidate);
    assertThat(candidate.getFile().toPath()).isNotEqualTo(candidateJar);
    assertThat(warnings)
        .anySatisfy(
            warning ->
                assertThat(warning)
                    .contains("root-module-info dependency unchanged")
                    .contains("covers classpath closure, not module-path closure"));
    try (JarFile original = new JarFile(passThrough.getFile());
        JarFile trimmed = new JarFile(candidate.getFile())) {
      assertThat(original.getEntry("module-info.class")).isNotNull();
      assertThat(trimmed.getEntry("candidate/Helper.class")).isNotNull();
      assertThat(trimmed.getEntry("candidate/Drop.class")).isNull();
    }
    try (URLClassLoader loader =
        new URLClassLoader(
            new URL[] {
              passThrough.getFile().toURI().toURL(), candidate.getFile().toURI().toURL()
            })) {
      assertThat(loader.loadClass("pass.Root").getMethod("call").invoke(null)).isEqualTo("ok");
    }
  }

  @Test
  void moduleInfoStrictModeFailsBeforePointerMutation()
      throws IOException, ReflectiveOperationException {
    final Path plainJar =
        compileJarSources(
            "module-info-strict", Map.of("Root.java", "package pass; public class Root {}"), null);
    final Path modularJar = addRootModuleDescriptor(plainJar, "strict.pass", "pass");
    final Artifact artifact = runtimeArtifact("module-info-strict", modularJar);
    final MavenProject project = projectForArtifacts("module-info-strict", Set.of(artifact));
    final byte[] originalBytes = Files.readAllBytes(modularJar);
    final ElideMojo mojo = newMojo();
    mojo.setLog(new SystemStreamLog());
    set(mojo, "project", project);
    set(mojo, "traceFiles", List.of(writeTrace("pass.Root\n").toFile()));
    set(mojo, "reportFile", tempDir.resolve("module-info-strict-report.json").toFile());
    set(mojo, "sbomFile", tempDir.resolve("module-info-strict-build/sbom.json").toFile());
    set(mojo, "trimJars", true);
    set(mojo, "failOnUnsupportedModuleInfo", true);

    assertThatThrownBy(mojo::execute)
        .isInstanceOf(MojoFailureException.class)
        .hasMessageContaining("Unsupported root module descriptor");
    assertThat(artifact.getFile().toPath()).isEqualTo(modularJar);
    assertThat(project.getArtifacts()).containsExactly(artifact);
    assertThat(Files.readAllBytes(modularJar)).isEqualTo(originalBytes);
  }

  private Path addRootModuleDescriptor(
      final Path sourceJar, final String moduleName, final String exportedPackage)
      throws IOException {
    final ClassWriter writer = new ClassWriter(0);
    writer.visit(Opcodes.V9, Opcodes.ACC_MODULE, "module-info", null, null, null);
    final ModuleVisitor module = writer.visitModule(moduleName, 0, null);
    module.visitRequire("java.base", 0, null);
    module.visitExport(exportedPackage.replace('.', '/'), 0);
    module.visitEnd();
    writer.visitEnd();
    final Path result = tempDir.resolve(sourceJar.getFileName() + "-modular.jar");
    try (JarFile input = new JarFile(sourceJar.toFile());
        ZipOutputStream output = new ZipOutputStream(Files.newOutputStream(result))) {
      final Enumeration<JarEntry> entries = input.entries();
      while (entries.hasMoreElements()) {
        final JarEntry entry = entries.nextElement();
        if (MODULE_INFO_CLASS.equals(entry.getName())) {
          continue;
        }
        output.putNextEntry(new ZipEntry(entry.getName()));
        try (InputStream content = input.getInputStream(entry)) {
          content.transferTo(output);
        }
        output.closeEntry();
      }
      output.putNextEntry(new ZipEntry(MODULE_INFO_CLASS));
      output.write(writer.toByteArray());
      output.closeEntry();
    }
    return result;
  }

  @Test
  void rootlessRetainedJarSeedsLinksIntoAnIndependentlyRootedSibling()
      throws IOException, ReflectiveOperationException, MojoFailureException {
    final Path callbackJar =
        compileJarSources(
            "callback",
            Map.of(
                "Callback.java",
                "package callback; public class Callback { public String invoke() { "
                    + "return \"callback\"; } }",
                "Independent.java",
                "package callback; public class Independent {}",
                "Unused.java",
                "package callback; public class Unused {}"),
            null);
    final Path helperJar =
        compileJarSources(
            "helper",
            Map.of(
                "Helper.java",
                "package callback; public class Helper { public static String call() { "
                    + "return new Callback().invoke(); } }"),
            callbackJar);
    final Artifact helper = runtimeArtifact("helper", helperJar);
    final Artifact callback = runtimeArtifact("callback", callbackJar);
    final Set<Artifact> artifacts = new LinkedHashSet<>(List.of(helper, callback));
    final MavenProject project = newProject();
    project.setArtifacts(artifacts);
    project.setDependencyArtifacts(new LinkedHashSet<>(artifacts));
    project.setGroupId("org.example");
    project.setArtifactId("rootless-consumer");
    project.setVersion("1.0");
    project.setName("Rootless Consumer");
    project.getProperties().setProperty("maven.compiler.release", "21");
    final Build build = new Build();
    build.setDirectory(tempDir.resolve("rootless-build").toString());
    project.setBuild(build);
    final ElideMojo mojo = newMojo();
    mojo.setLog(new SystemStreamLog());
    set(mojo, "project", project);
    set(mojo, "traceFiles", List.of(writeTrace("callback.Independent\n").toFile()));
    set(mojo, "excludedArtifacts", List.of("org.example:helper"));
    set(mojo, "reportFile", tempDir.resolve("rootless-report.json").toFile());
    set(mojo, "sbomFile", tempDir.resolve("rootless-build/rootless-sbom.json").toFile());
    set(mojo, "trimJars", true);

    mojo.execute();

    assertThat(helper.getFile().toPath()).isEqualTo(helperJar);
    assertJarContains(callback, "callback/Callback.class");
    try (URLClassLoader loader =
        new URLClassLoader(
            new URL[] {helper.getFile().toURI().toURL(), callback.getFile().toURI().toURL()})) {
      assertThat(loader.loadClass("callback.Helper").getMethod("call").invoke(null))
          .isEqualTo("callback");
    }
    try (JarFile trimmed = new JarFile(callback.getFile())) {
      assertThat(trimmed.getEntry("callback/Unused.class")).isNull();
    }
  }

  @Test
  void malformedSpringMetadataFailsBeforeArtifactMutation()
      throws IOException, ReflectiveOperationException {
    final Artifact used = artifact("used", "used/Sample.class");
    final Path original = used.getFile().toPath();
    used.setFile(
        rewriteJar(
                original,
                Map.of(
                    "META-INF/spring-autoconfigure-metadata.properties", "not-a-supported-key=x\n"))
            .toFile());
    final Path malformed = used.getFile().toPath();
    final MavenProject project = project(used, new LinkedHashSet<>(List.of(used)));
    project.setGroupId("org.example");
    project.setArtifactId("consumer");
    project.setVersion("1.0");
    final Build build = new Build();
    build.setDirectory(tempDir.resolve("malformed-build").toString());
    project.setBuild(build);
    final ElideMojo mojo = newMojo();
    mojo.setLog(new SystemStreamLog());
    set(mojo, "project", project);
    set(mojo, "traceFiles", List.of(writeTrace("used.Sample\n").toFile()));
    set(mojo, "reportFile", tempDir.resolve("malformed-report.json").toFile());
    set(mojo, "trimJars", true);

    assertThatThrownBy(mojo::execute)
        .isInstanceOf(MojoFailureException.class)
        .hasMessageContaining("Unsupported Spring autoconfigure metadata key");
    assertThat(used.getFile().toPath()).isEqualTo(malformed).isNotEqualTo(original);
    assertThat(project.getArtifacts()).contains(used);
  }

  @Test
  void unsupportedNativeImageArgsFailBeforeArtifactMutation()
      throws IOException, ReflectiveOperationException {
    final Artifact used = artifact("native-image-unsupported", "used/Sample.class");
    final Path original = used.getFile().toPath();
    used.setFile(
        rewriteJar(
                original,
                Map.of(
                    "META-INF/native-image/test/native-image.properties",
                    "Args=-H:Class=example.NativeEntry\n"))
            .toFile());
    final Path input = used.getFile().toPath();
    final MavenProject project = project(used, new LinkedHashSet<>(List.of(used)));
    project.setGroupId("org.example");
    project.setArtifactId("native-image-consumer");
    project.setVersion("1.0");
    final Build build = new Build();
    build.setDirectory(tempDir.resolve("native-image-build").toString());
    project.setBuild(build);
    final ElideMojo mojo = newMojo();
    mojo.setLog(new SystemStreamLog());
    set(mojo, "project", project);
    set(mojo, "traceFiles", List.of(writeTrace("used.Sample\n").toFile()));
    set(mojo, "reportFile", tempDir.resolve("native-image-report.json").toFile());
    set(mojo, "trimJars", true);

    assertThatThrownBy(mojo::execute)
        .isInstanceOf(MojoFailureException.class)
        .hasMessageContaining("Unsupported native-image Args");
    assertThat(used.getFile().toPath()).isEqualTo(input).isNotEqualTo(original);
    assertThat(project.getArtifacts()).contains(used);
  }

  @Test
  void malformedNativeImageResourceBundlesFailBeforeArtifactMutation()
      throws IOException, ReflectiveOperationException {
    final Artifact used = artifact("native-image-malformed", "used/Sample.class");
    final Path original = used.getFile().toPath();
    used.setFile(
        rewriteJar(
                original,
                Map.of(
                    "META-INF/native-image/test/test-resource.json",
                    "{\"bundles\":\"not-an-array\"}"))
            .toFile());
    final Path input = used.getFile().toPath();
    final MavenProject project = project(used, new LinkedHashSet<>(List.of(used)));
    project.setGroupId("org.example");
    project.setArtifactId("native-image-consumer");
    project.setVersion("1.0");
    final Build build = new Build();
    build.setDirectory(tempDir.resolve("native-image-malformed-build").toString());
    project.setBuild(build);
    final ElideMojo mojo = newMojo();
    mojo.setLog(new SystemStreamLog());
    set(mojo, "project", project);
    set(mojo, "traceFiles", List.of(writeTrace("used.Sample\n").toFile()));
    set(mojo, "reportFile", tempDir.resolve("native-image-malformed-report.json").toFile());
    set(mojo, "trimJars", true);

    assertThatThrownBy(mojo::execute)
        .isInstanceOf(MojoFailureException.class)
        .hasMessageContaining("Malformed native-image bundles section");
    assertThat(used.getFile().toPath()).isEqualTo(input).isNotEqualTo(original);
    assertThat(project.getArtifacts()).contains(used);
  }

  @Test
  void trimCacheFingerprintTracksExactOrderedAnalysisInputs() throws IOException {
    final Path firstLibrary = tempDir.resolve("first.jar");
    final Path secondLibrary = tempDir.resolve("second.jar");
    final Path ctSym = tempDir.resolve("ct.sym");
    final Path otherJdkCtSym = tempDir.resolve("other-jdk/lib/ct.sym");
    final Path jmod = tempDir.resolve("java.base.jmod");
    Files.writeString(firstLibrary, "first-bytes");
    Files.writeString(secondLibrary, "second-bytes");
    Files.writeString(ctSym, "ct-sym-bytes");
    Files.createDirectories(otherJdkCtSym.getParent());
    Files.writeString(otherJdkCtSym, "other-jdk-platform-bytes");
    Files.writeString(jmod, "jmod-bytes");
    final FileTime timestamp = FileTime.fromMillis(1_700_000_000_000L);
    Files.setLastModifiedTime(firstLibrary, timestamp);
    Files.setLastModifiedTime(ctSym, timestamp);
    final List<String> candidateIdentities = List.of("org.example:first:1.0:jar");
    final String baseline =
        MavenDependencyTrimmer.fingerprintForInputs(
            candidateIdentities,
            List.of(firstLibrary, secondLibrary),
            Set.of("sample.Root"),
            List.of(ctSym),
            21,
            4,
            "proguard-core-9.4.0");

    assertThat(
            MavenDependencyTrimmer.fingerprintForInputs(
                candidateIdentities,
                List.of(secondLibrary, firstLibrary),
                Set.of("sample.Root"),
                List.of(ctSym),
                21,
                4,
                "proguard-core-9.4.0"))
        .isNotEqualTo(baseline);
    assertThat(
            MavenDependencyTrimmer.fingerprintForInputs(
                candidateIdentities,
                List.of(firstLibrary, secondLibrary),
                Set.of("sample.Root"),
                List.of(ctSym),
                17,
                4,
                "proguard-core-9.4.0"))
        .isNotEqualTo(baseline);
    assertThat(
            MavenDependencyTrimmer.fingerprintForInputs(
                candidateIdentities,
                List.of(firstLibrary, secondLibrary),
                Set.of("sample.Root"),
                List.of(otherJdkCtSym),
                21,
                4,
                "proguard-core-9.4.0"))
        .isNotEqualTo(baseline);
    assertThat(
            MavenDependencyTrimmer.fingerprintForInputs(
                candidateIdentities,
                List.of(firstLibrary, secondLibrary),
                Set.of("sample.OtherRoot"),
                List.of(ctSym),
                21,
                4,
                "proguard-core-9.4.0"))
        .isNotEqualTo(baseline);
    assertThat(
            MavenDependencyTrimmer.fingerprintForInputs(
                candidateIdentities,
                List.of(firstLibrary, secondLibrary),
                Set.of("sample.Root"),
                List.of(jmod),
                21,
                4,
                "proguard-core-9.4.0"))
        .isNotEqualTo(baseline);
    assertThat(
            MavenDependencyTrimmer.fingerprintForInputs(
                candidateIdentities,
                List.of(firstLibrary, secondLibrary),
                Set.of("sample.Root"),
                List.of(ctSym, jmod),
                21,
                4,
                "proguard-core-9.4.0"))
        .isNotEqualTo(baseline);
    assertThat(
            MavenDependencyTrimmer.fingerprintForInputs(
                candidateIdentities,
                List.of(firstLibrary, secondLibrary),
                Set.of("sample.Root"),
                List.of(ctSym),
                21,
                5,
                "proguard-core-9.4.0"))
        .isNotEqualTo(baseline);
    assertThat(
            MavenDependencyTrimmer.fingerprintForInputs(
                candidateIdentities,
                List.of(firstLibrary, secondLibrary),
                Set.of("sample.Root"),
                List.of(ctSym),
                21,
                4,
                "proguard-core-9.4.1"))
        .isNotEqualTo(baseline);

    Files.writeString(firstLibrary, "other-bytes");
    Files.setLastModifiedTime(firstLibrary, timestamp);
    final String dependencyChangedFingerprint =
        MavenDependencyTrimmer.fingerprintForInputs(
            candidateIdentities,
            List.of(firstLibrary, secondLibrary),
            Set.of("sample.Root"),
            List.of(ctSym),
            21,
            4,
            "proguard-core-9.4.0");
    assertThat(dependencyChangedFingerprint).isNotEqualTo(baseline);
    final long ctSymSize = Files.size(ctSym);
    Files.writeString(ctSym, "xt-sym-bytes");
    Files.setLastModifiedTime(ctSym, timestamp);
    assertThat(Files.size(ctSym)).isEqualTo(ctSymSize);
    assertThat(Files.getLastModifiedTime(ctSym)).isEqualTo(timestamp);
    assertThat(
            MavenDependencyTrimmer.fingerprintForInputs(
                candidateIdentities,
                List.of(firstLibrary, secondLibrary),
                Set.of("sample.Root"),
                List.of(ctSym),
                21,
                4,
                "proguard-core-9.4.0"))
        .isNotEqualTo(dependencyChangedFingerprint);
  }

  @Test
  void trimCacheMissesWhenCandidateOrRetainedSiblingContentChangesAtSameSizeAndTimestamp()
      throws Exception {
    final Path siblingJar =
        compileJarSources(
            "digest-sibling",
            Map.of(
                "Use.java",
                "package helper; public class Use {}",
                "Drop.java",
                "package helper; public class Drop {}"),
            null);
    final Path candidateJar =
        compileJarSources(
            "digest-candidate",
            Map.of(
                "Keep.java", "package sample; public class Keep { helper.Use use; }",
                "Drop.java", "package sample; public class Drop {}"),
            siblingJar);
    final FileTime sourceTimestamp = FileTime.fromMillis(1_700_000_000_000L);
    rewriteStoredJar(candidateJar, null, null, sourceTimestamp);
    rewriteStoredJar(siblingJar, null, null, sourceTimestamp);
    final Artifact candidate = runtimeArtifact("digest-candidate", candidateJar);
    final Artifact sibling = runtimeArtifact("digest-sibling", siblingJar);
    final MavenProject project =
        project(candidate, new LinkedHashSet<>(List.of(candidate, sibling)), sibling);
    project.setGroupId("org.example");
    project.setArtifactId("digest-cache-consumer");
    project.setVersion("1.0");
    project.getProperties().setProperty("maven.compiler.release", "21");
    final Build build = new Build();
    build.setDirectory(tempDir.resolve("digest-cache-build").toString());
    project.setBuild(build);

    assertThat(analyzeTrim(project, "sample.Keep\nhelper.Use\n").trimAnalysisRuns()).isPositive();
    assertThat(analyzeTrim(project, "sample.Keep\nhelper.Use\n").trimAnalysisRuns()).isZero();

    final long candidateSize = Files.size(candidateJar);
    rewriteStoredJar(
        candidateJar,
        "sample/Keep.class",
        toggleFinalClassFlag(candidateJar, "sample/Keep.class"),
        sourceTimestamp);
    assertThat(Files.size(candidateJar)).isEqualTo(candidateSize);
    assertThat(Files.getLastModifiedTime(candidateJar)).isEqualTo(sourceTimestamp);
    assertThat(analyzeTrim(project, "sample.Keep\nhelper.Use\n").trimAnalysisRuns()).isPositive();

    final long siblingSize = Files.size(siblingJar);
    rewriteStoredJar(
        siblingJar,
        "helper/Use.class",
        toggleFinalClassFlag(siblingJar, "helper/Use.class"),
        sourceTimestamp);
    assertThat(Files.size(siblingJar)).isEqualTo(siblingSize);
    assertThat(Files.getLastModifiedTime(siblingJar)).isEqualTo(sourceTimestamp);
    assertThat(analyzeTrim(project, "sample.Keep\nhelper.Use\n").trimAnalysisRuns()).isPositive();
  }

  @Test
  void explicitTrimRootKeepsItsWholeArtifactOwnerAndTrimsOtherClasses()
      throws IOException, ReflectiveOperationException, MojoFailureException {
    final Artifact used =
        runtimeArtifact(
            "used",
            compileJarSources(
                "used", Map.of("Sample.java", "package used; public class Sample {}"), null));
    final Path explicitJar =
        compileJarSources(
            "explicit",
            Map.of(
                "Keep.java", "package explicit; public class Keep {}",
                "Drop.java", "package explicit; public class Drop {}"),
            null);
    final Artifact explicit = runtimeArtifact("explicit", explicitJar);
    final Set<Artifact> artifacts = new LinkedHashSet<>(List.of(used, explicit));
    final MavenProject project = newProject();
    project.setArtifacts(artifacts);
    project.setDependencyArtifacts(new LinkedHashSet<>(artifacts));
    project.setGroupId("org.example");
    project.setArtifactId("explicit-consumer");
    project.setVersion("1.0");
    project.getProperties().setProperty("maven.compiler.release", "21");
    final Build build = new Build();
    build.setDirectory(tempDir.resolve("explicit-build").toString());
    project.setBuild(build);
    final ElideMojo mojo = newMojo();
    mojo.setLog(new SystemStreamLog());
    set(mojo, "project", project);
    set(mojo, "traceFiles", List.of(writeTrace("used.Sample\n").toFile()));
    set(mojo, "trimRoots", List.of("explicit.Keep"));
    set(mojo, "reportFile", tempDir.resolve("explicit-report.json").toFile());
    set(mojo, "sbomFile", tempDir.resolve("explicit-build/explicit-sbom.json").toFile());
    set(mojo, "trimJars", true);

    mojo.execute();

    assertThat(project.getArtifacts()).contains(explicit);
    assertJarContains(explicit, "explicit/Keep.class");
    try (JarFile trimmed = new JarFile(explicit.getFile())) {
      assertThat(trimmed.getEntry("explicit/Drop.class")).isNull();
    }
  }

  @Test
  void trimSbomIncludesRetainedPomArtifacts()
      throws IOException, ReflectiveOperationException, MojoFailureException {
    final Path dependencyJar =
        compileJarSources(
            "sbom-dependency",
            Map.of(
                "Keep.java", "package sbom; public class Keep {}",
                "Drop.java", "package sbom; public class Drop {}"),
            null);
    final Artifact jarArtifact = runtimeArtifact("sbom-dependency", dependencyJar);
    final Path pomFile = tempDir.resolve("descriptor-dependency.pom");
    Files.writeString(pomFile, "<project/>\n");
    final Artifact pomArtifact =
        new DefaultArtifact(
            "org.example",
            "descriptor-dependency",
            "1.0",
            "runtime",
            "pom",
            null,
            new DefaultArtifactHandler("pom"));
    pomArtifact.setFile(pomFile.toFile());
    final Set<Artifact> artifacts = new LinkedHashSet<>(List.of(jarArtifact, pomArtifact));
    final MavenProject project = newProject();
    project.setArtifacts(artifacts);
    project.setDependencyArtifacts(new LinkedHashSet<>(artifacts));
    project.setGroupId("org.example");
    project.setArtifactId("sbom-consumer");
    project.setVersion("1.0");
    project.setName("SBOM Consumer");
    project.getProperties().setProperty("maven.compiler.release", "21");
    final Build build = new Build();
    build.setDirectory(tempDir.resolve("pom-sbom-build").toString());
    project.setBuild(build);
    final ElideMojo mojo = newMojo();
    mojo.setLog(new SystemStreamLog());
    set(mojo, "project", project);
    set(mojo, "traceFiles", List.of(writeTrace("sbom.Keep\n").toFile()));
    set(mojo, "reportFile", tempDir.resolve("pom-sbom-report.json").toFile());
    set(mojo, "sbomFile", tempDir.resolve("pom-sbom-build/sbom.json").toFile());
    set(mojo, "trimJars", true);

    mojo.execute();

    assertThat(project.getArtifacts()).contains(jarArtifact, pomArtifact);
    assertThat(tempDir.resolve("pom-sbom-build/sbom.json")).isRegularFile();
    assertJarContains(jarArtifact, "sbom/Keep.class");
    try (JarFile trimmed = new JarFile(jarArtifact.getFile())) {
      assertThat(trimmed.getEntry("sbom/Drop.class")).isNull();
    }
  }

  private Artifact compiledArtifact() throws IOException {
    final Path jar = tempDir.resolve("runtime-dependency.jar");
    final Path sourceDirectory = tempDir.resolve("trim-src");
    io.github.spockz.elider.test.CompilationFixtureSupport.compileToJar(
        jar,
        sourceDirectory,
        Map.of(
            "sample/Keep.java", "package sample; public class Keep { Helper helper; }",
            "sample/Helper.java", "package sample; public class Helper {}",
            "sample/Drop.java", "package sample; public class Drop {}"),
        null);
    final Artifact artifact =
        new DefaultArtifact(
            "org.example",
            "runtime-dependency",
            "1.0",
            "runtime",
            "jar",
            null,
            new DefaultArtifactHandler("jar"));
    artifact.setFile(jar.toFile());
    return artifact;
  }

  private Path compileJar(final String className, final String source, final Path classpath)
      throws IOException {
    return compileJarSources(className, Map.of(className + ".java", source), classpath);
  }

  private Path compileJarSources(
      final String jarName, final Map<String, String> sources, final Path classpath)
      throws IOException {
    return compileJarSources(jarName, sources, classpath, 21);
  }

  private Path compileJarSources(
      final String jarName,
      final Map<String, String> sources,
      final Path classpath,
      final int release)
      throws IOException {
    final Path jar = tempDir.resolve(jarName + ".jar");
    final Path sourceDirectory = tempDir.resolve(jarName + "-src");
    return io.github.spockz.elider.test.CompilationFixtureSupport.compileToJar(
        jar, sourceDirectory, sources, classpath, release);
  }

  private static byte[] toggleFinalClassFlag(final Path jar, final String entryName)
      throws IOException {
    try (JarFile input = new JarFile(jar.toFile())) {
      final JarEntry entry = input.getJarEntry(entryName);
      if (entry == null) {
        throw new IOException("Missing test class entry: " + entryName);
      }
      final byte[] original;
      try (InputStream classInput = input.getInputStream(entry)) {
        original = classInput.readAllBytes();
      }
      final ClassReader reader = new ClassReader(original);
      final ClassWriter writer = new ClassWriter(reader, 0);
      reader.accept(
          new ClassVisitor(Opcodes.ASM9, writer) {
            @Override
            public void visit(
                final int version,
                final int access,
                final String name,
                final String signature,
                final String superName,
                final String[] interfaces) {
              super.visit(
                  version, access ^ Opcodes.ACC_FINAL, name, signature, superName, interfaces);
            }
          },
          0);
      return writer.toByteArray();
    }
  }

  private void rewriteStoredJar(
      final Path jar,
      final String replacedEntry,
      final byte[] replacementBytes,
      final FileTime timestamp)
      throws IOException {
    final Path rewrittenJar = jar.resolveSibling(jar.getFileName() + ".rewrite");
    boolean replaced = replacedEntry == null;
    try (JarFile input = new JarFile(jar.toFile());
        ZipOutputStream output = new ZipOutputStream(Files.newOutputStream(rewrittenJar))) {
      final Enumeration<JarEntry> entries = input.entries();
      while (entries.hasMoreElements()) {
        final JarEntry entry = entries.nextElement();
        final byte[] contents;
        if (entry.getName().equals(replacedEntry)) {
          contents = replacementBytes;
          replaced = true;
        } else {
          try (InputStream stream = input.getInputStream(entry)) {
            contents = stream.readAllBytes();
          }
        }
        final CRC32 crc = new CRC32();
        crc.update(contents);
        final ZipEntry stored = new ZipEntry(entry.getName());
        stored.setMethod(ZipEntry.STORED);
        stored.setSize(contents.length);
        stored.setCompressedSize(contents.length);
        stored.setCrc(crc.getValue());
        stored.setTime(timestamp.toMillis());
        output.putNextEntry(stored);
        output.write(contents);
        output.closeEntry();
      }
    }
    if (!replaced) {
      throw new IOException("Missing test archive entry to replace: " + replacedEntry);
    }
    Files.move(rewrittenJar, jar, StandardCopyOption.REPLACE_EXISTING);
    Files.setLastModifiedTime(jar, timestamp);
  }

  private static MavenDependencyTrimmer.TrimRequest tieredRequest(
      final MavenElisionService.PreparedAnalysis prepared,
      final Set<ArtifactCoordinate> retainedCoordinates) {
    final MavenElisionService.AnalysisOptions options = prepared.options();
    return new MavenDependencyTrimmer.TrimRequest(
        prepared.project(),
        options.session(),
        prepared.resolvedSnapshots(),
        new MavenDependencyTrimmer.ScanInputs(
            prepared.index(), prepared.dynamicRootInputs().scansByPath()),
        retainedCoordinates,
        prepared.trace(),
        prepared.pruningRequiredClasses(),
        prepared.bytecodeScan().map(BytecodeReferenceScan::referencedClasses).orElse(Set.of()),
        prepared.projectOutputClasses(),
        options.explicitTrimRoots(),
        options.failOnUnsupportedMultiRelease(),
        options.explicitPassThroughArtifacts(),
        options.failOnUnsupportedModuleInfo(),
        options.mrjarStrategy(),
        options.trimJars(),
        prepared.dynamicRootInputs().provenServiceInterfaces(),
        options.conservativeServiceLoaderRoots(),
        options.trimWorkers());
  }

  private static Set<ArtifactCoordinate> union(
      final Set<ArtifactCoordinate> coordinates, final ArtifactCoordinate coordinate) {
    final Set<ArtifactCoordinate> result = new LinkedHashSet<>(coordinates);
    result.add(coordinate);
    return Set.copyOf(result);
  }

  private MultiReleaseFixture multiReleaseFixture(final String name) throws IOException {
    return multiReleaseFixture(name, false);
  }

  private MultiReleaseFixture multiReleaseFixture(
      final String name, final boolean targetUsesTargetSupport) throws IOException {
    final Path candidatePath =
        compileJarSources(
            name + "-candidate",
            Map.of(
                "Keep.java",
                "package candidate; public class Keep {}",
                "BaseSupport.java",
                "package candidate; public class BaseSupport { public void touch() { "
                    + "new BaseTail().touch(); } }",
                "BaseTail.java",
                "package candidate; public class BaseTail { public void touch() {} }",
                "TargetSupport.java",
                "package candidate; public class TargetSupport { public void touch() { "
                    + "new TargetTail().touch(); } }",
                "TargetTail.java",
                "package candidate; public class TargetTail { public void touch() {} }",
                "UpperSupport.java",
                "package candidate; public class UpperSupport { public void touch() { "
                    + "new UpperTail().touch(); } }",
                "UpperTail.java",
                "package candidate; public class UpperTail { public void touch() {} }",
                "Drop.java",
                "package candidate; public class Drop {}"),
            null,
            8);
    final Path rootClasses =
        compileJarSources(
            name + "-root-classes",
            Map.of(
                "Root.java",
                "package mrroot; public class Root { public static void execute() { "
                    + "new candidate.BaseSupport().touch(); } }",
                "RootHelper.java",
                "package mrroot; public class RootHelper { public void execute() { "
                    + "new candidate.TargetSupport().touch(); "
                    + "new candidate.UpperSupport().touch(); } }"),
            candidatePath,
            8);
    final Path targetRoot =
        compileJarSources(
            name + "-target-root",
            Map.of(
                "Root.java",
                targetUsesTargetSupport
                    ? "package mrroot; public class Root { public static void execute() { "
                        + "new candidate.TargetSupport().touch(); } }"
                    : "package mrroot; public class Root { public static void execute() {} }"),
            candidatePath,
            11);
    final Path versionOnly =
        compileJarSources(
            name + "-version-only",
            Map.of(
                "Root.java",
                "package mrroot; public class Root { public static void execute() { "
                    + "new RootHelper().execute(); } }",
                "VersionOnly.java",
                "package mrroot; class VersionOnly {}",
                "UnusedUpperFeature.java",
                "package mrroot; class UnusedUpperFeature {}"),
            rootClasses,
            17);
    final Path unusedJava17Root =
        compileJarSources(
            name + "-unused-java17-root",
            Map.of("UnusedJava17.java", "package mrroot; public class UnusedJava17 {}"),
            null,
            17);
    final Path multiReleasePath =
        writeMultiReleaseJar(
            name + "-root.jar", rootClasses, unusedJava17Root, targetRoot, versionOnly, Map.of());
    final Artifact root = runtimeArtifact(name + "-root", multiReleasePath);
    final Artifact candidate = runtimeArtifact(name + "-candidate", candidatePath);
    final Set<Artifact> artifacts = new LinkedHashSet<>(List.of(root, candidate));
    final MavenProject project = newProject();
    project.setArtifacts(artifacts);
    project.setDependencyArtifacts(new LinkedHashSet<>(artifacts));
    project.setGroupId("org.example");
    project.setArtifactId(name + "-consumer");
    project.setVersion("1.0");
    project.getProperties().setProperty("maven.compiler.release", "11");
    final Build build = new Build();
    build.setDirectory(tempDir.resolve(name + "-build").toString());
    project.setBuild(build);
    return new MultiReleaseFixture(root, candidate, multiReleasePath, candidatePath, project);
  }

  private SpringOptionalMrjarInput springOptionalMrjarInput(final String name) throws IOException {
    final Path candidatePath =
        compileJarSources(
            name + "-candidate",
            Map.of(
                "Keep.java",
                "package candidate; public class Keep { public void touch() {} }",
                "Entry.java",
                "package candidate; public class Entry {}",
                "Drop.java",
                "package candidate; public class Drop {}"),
            null,
            8);
    final Path optionalTypePath =
        compileJarSources(
            name + "-optional-kotlin-types",
            Map.of("Continuation.java", "package kotlin.coroutines; public class Continuation {}"),
            null,
            8);
    final Path coreCompileClasspath =
        Path.of(candidatePath + java.io.File.pathSeparator + optionalTypePath);
    final String coreClass =
        "package org.springframework.core; public class CoroutinesUtils { "
            + "public static void invoke() { new candidate.Keep().touch(); "
            + "new kotlin.coroutines.Continuation(); } }";
    final Path coreBase =
        compileJarSources(
            name + "-spring-core-base",
            Map.of("CoroutinesUtils.java", coreClass),
            coreCompileClasspath,
            8);
    final Path coreTarget =
        compileJarSources(
            name + "-spring-core-target",
            Map.of("CoroutinesUtils.java", coreClass),
            coreCompileClasspath,
            11);
    final Path coreUpper =
        compileJarSources(
            name + "-spring-core-upper",
            Map.of("CoroutinesUtils.java", coreClass),
            coreCompileClasspath,
            17);
    final Path springCorePath =
        writeMultiReleaseJar(
            name + "-spring-core.jar", coreBase, null, coreTarget, coreUpper, Map.of());
    final Path springAopPath =
        compileJarSources(
            name + "-spring-aop",
            Map.of(
                "AopRoot.java",
                "package org.springframework.aop; public class AopRoot { "
                    + "public static void invoke() { "
                    + "org.springframework.core.CoroutinesUtils.invoke(); } }"),
            springCorePath);
    return new SpringOptionalMrjarInput(springAopPath, springCorePath, candidatePath);
  }

  private MavenProject projectForArtifacts(final String name, final Set<Artifact> artifacts) {
    final MavenProject project = newProject();
    project.setArtifacts(artifacts);
    project.setDependencyArtifacts(new LinkedHashSet<>(artifacts));
    project.setGroupId("org.example");
    project.setArtifactId(name);
    project.setVersion("1.0");
    project.getProperties().setProperty("maven.compiler.release", "21");
    final Build build = new Build();
    build.setDirectory(tempDir.resolve(name + "-build").toString());
    project.setBuild(build);
    return project;
  }

  private Path writeJarWithoutClass(
      final String outputName, final Path source, final String omittedClass) throws IOException {
    final Path outputJar = tempDir.resolve(outputName);
    try (JarFile input = new JarFile(source.toFile());
        java.util.jar.JarOutputStream output =
            new java.util.jar.JarOutputStream(Files.newOutputStream(outputJar))) {
      final Enumeration<JarEntry> entries = input.entries();
      while (entries.hasMoreElements()) {
        final JarEntry entry = entries.nextElement();
        if (entry.isDirectory() || entry.getName().equals(omittedClass)) {
          continue;
        }
        output.putNextEntry(new JarEntry(entry.getName()));
        try (InputStream contents = input.getInputStream(entry)) {
          contents.transferTo(output);
        }
        output.closeEntry();
      }
    }
    return outputJar;
  }

  private Path writeMultiReleaseJar(
      final String name,
      final Path baseJar,
      final Path additionalRootJar,
      final Path targetVersionJar,
      final Path upperVersionJar,
      final Map<String, String> rootResources)
      throws IOException {
    final Path result = tempDir.resolve(name);
    final java.util.jar.Manifest manifest = new java.util.jar.Manifest();
    manifest.getMainAttributes().put(java.util.jar.Attributes.Name.MANIFEST_VERSION, "1.0");
    manifest.getMainAttributes().putValue("Multi-Release", "true");
    try (JarFile base = new JarFile(baseJar.toFile());
        JarFile targetVersion = new JarFile(targetVersionJar.toFile());
        JarFile upperVersion = new JarFile(upperVersionJar.toFile());
        java.util.jar.JarOutputStream output =
            new java.util.jar.JarOutputStream(Files.newOutputStream(result), manifest)) {
      copyJarEntries(base, output, "");
      if (additionalRootJar != null) {
        try (JarFile additionalRoot = new JarFile(additionalRootJar.toFile())) {
          copyJarEntries(additionalRoot, output, "");
        }
      }
      copyJarEntries(targetVersion, output, "META-INF/versions/11/");
      copyJarEntries(upperVersion, output, "META-INF/versions/17/");
      for (final Map.Entry<String, String> entry : rootResources.entrySet()) {
        output.putNextEntry(new JarEntry(entry.getKey()));
        output.write(entry.getValue().getBytes(java.nio.charset.StandardCharsets.UTF_8));
        output.closeEntry();
      }
    }
    return result;
  }

  private static void copyJarEntries(
      final JarFile source, final java.util.jar.JarOutputStream output, final String prefix)
      throws IOException {
    final Enumeration<JarEntry> entries = source.entries();
    while (entries.hasMoreElements()) {
      final JarEntry entry = entries.nextElement();
      if (entry.isDirectory()
          || !entry.getName().endsWith(".class")
          || "org/example/optional/ScriptEvaluator.class".equals(entry.getName())) {
        continue;
      }
      output.putNextEntry(new JarEntry(prefix + entry.getName()));
      try (InputStream contents = source.getInputStream(entry)) {
        contents.transferTo(output);
      }
      output.closeEntry();
    }
  }

  // Log's defining loader must define the proxy interface used by the fixture.
  @SuppressWarnings("PMD.UseProperClassLoader")
  private static Log recordingLog(final List<String> warnings) {
    return (Log)
        Proxy.newProxyInstance(
            Log.class.getClassLoader(),
            new Class<?>[] {Log.class},
            (proxy, method, arguments) -> {
              if ("warn".equals(method.getName())
                  && arguments != null
                  && arguments.length > 0
                  && arguments[0] instanceof CharSequence message) {
                warnings.add(message.toString());
              }
              return method.getReturnType() == boolean.class ? false : null;
            });
  }

  private record MultiReleaseFixture(
      Artifact multiRelease,
      Artifact candidate,
      Path multiReleasePath,
      Path candidatePath,
      MavenProject project) {}

  private record SpringOptionalMrjarInput(
      Path springAopPath, Path springCorePath, Path candidatePath) {}

  private static byte[] jarEntryBytes(final Path archive, final String entryName)
      throws IOException {
    try (JarFile jar = new JarFile(archive.toFile())) {
      return jarEntryBytes(jar, entryName);
    }
  }

  private static byte[] jarEntryBytes(final JarFile jar, final String entryName)
      throws IOException {
    final JarEntry entry = jar.getJarEntry(entryName);
    if (entry == null) {
      throw new IOException("Missing test archive entry: " + entryName);
    }
    try (InputStream input = jar.getInputStream(entry)) {
      return input.readAllBytes();
    }
  }

  private static String componentProperty(final JsonNode component, final String name) {
    for (final JsonNode property : component.path("properties")) {
      if (name.equals(property.path("name").asText())) {
        return property.path("value").asText();
      }
    }
    throw new AssertionError("Missing SBOM component property: " + name);
  }

  private Path descriptorJar(final String name, final String entry, final String content)
      throws IOException {
    final Path jar = tempDir.resolve(name);
    try (ZipOutputStream output = new ZipOutputStream(Files.newOutputStream(jar))) {
      output.putNextEntry(new ZipEntry(entry));
      output.write(content.getBytes(java.nio.charset.StandardCharsets.UTF_8));
      output.closeEntry();
    }
    return jar;
  }

  private Path rewriteJar(final Path original, final Map<String, String> resources)
      throws IOException {
    final Path outputJar = tempDir.resolve("with-metadata-" + original.getFileName());
    try (JarFile inputJar = new JarFile(original.toFile());
        ZipOutputStream output = new ZipOutputStream(Files.newOutputStream(outputJar))) {
      final Enumeration<JarEntry> entries = inputJar.entries();
      while (entries.hasMoreElements()) {
        final ZipEntry entry = entries.nextElement();
        output.putNextEntry(new ZipEntry(entry.getName()));
        try (InputStream stream = inputJar.getInputStream(entry)) {
          stream.transferTo(output);
        }
        output.closeEntry();
      }
      for (final Map.Entry<String, String> resource : resources.entrySet()) {
        output.putNextEntry(new ZipEntry(resource.getKey()));
        output.write(resource.getValue().getBytes(java.nio.charset.StandardCharsets.UTF_8));
        output.closeEntry();
      }
    }
    return outputJar;
  }

  private Path selectJarEntries(
      final Path sourceJar, final String outputName, final Set<String> selectedEntries)
      throws IOException {
    final Path outputJar = tempDir.resolve(outputName);
    try (JarFile inputJar = new JarFile(sourceJar.toFile());
        ZipOutputStream output = new ZipOutputStream(Files.newOutputStream(outputJar))) {
      for (final String entryName : selectedEntries) {
        final JarEntry entry = inputJar.getJarEntry(entryName);
        if (entry == null) {
          throw new IOException("Missing cycle fixture entry: " + entryName);
        }
        output.putNextEntry(new ZipEntry(entryName));
        try (InputStream stream = inputJar.getInputStream(entry)) {
          stream.transferTo(output);
        }
        output.closeEntry();
      }
    }
    return outputJar;
  }

  private Artifact runtimeArtifact(final String artifactId, final Path jar) {
    final Artifact artifact =
        new DefaultArtifact(
            "org.example",
            artifactId,
            "1.0",
            "runtime",
            "jar",
            null,
            new DefaultArtifactHandler("jar"));
    artifact.setFile(jar.toFile());
    return artifact;
  }

  private void assertJarContains(final Artifact artifact, final String entry) throws IOException {
    assertThat(artifact.getFile().toPath())
        .isNotEqualTo(tempDir.resolve(artifact.getArtifactId() + ".jar"));
    try (JarFile jar = new JarFile(artifact.getFile())) {
      assertThat(jar.getEntry(entry)).isNotNull();
    }
  }

  private void assertJarEntryPresent(final Artifact artifact, final String entry)
      throws IOException {
    try (JarFile jar = new JarFile(artifact.getFile())) {
      assertThat(jar.getEntry(entry)).isNotNull();
    }
  }

  private void assertJarOmits(final Artifact artifact, final String entry) throws IOException {
    try (JarFile jar = new JarFile(artifact.getFile())) {
      assertThat(jar.getEntry(entry)).isNull();
    }
  }

  private Path writeTrace(final String content) throws IOException {
    final Path trace = tempDir.resolve("trim-runtime.lst");
    Files.writeString(trace, content);
    return trace;
  }

  @Test
  void preservesAbsentAndPresentEmptyDirectViews()
      throws IOException, ReflectiveOperationException, MojoFailureException {
    final Artifact used = artifact("used", "used/Sample.class");
    final MavenProject absent = project(used, null);
    final MavenProject presentEmpty = project(used, new LinkedHashSet<>());

    execute(absent, "used/Sample\n");
    execute(presentEmpty, "used/Sample\n");

    assertThat(absent.getDependencyArtifacts()).isNull();
    assertThat(presentEmpty.getDependencyArtifacts()).isEmpty();
  }

  @Test
  void invalidTraceFailsWithoutChangingEitherArtifactView()
      throws IOException, ReflectiveOperationException {
    final Artifact used = artifact("used", "used/Sample.class");
    final Artifact unused = artifact("unused", "unused/Idle.class");
    final MavenProject project = project(used, new LinkedHashSet<>(List.of(used, unused)), unused);
    final Set<Artifact> resolvedBefore = project.getArtifacts();
    final Set<Artifact> directBefore = project.getDependencyArtifacts();

    assertThatThrownBy(() -> execute(project, "missing/Sample\n"))
        .isInstanceOf(MojoFailureException.class)
        .hasMessageContaining("no observed class matches any supplied dependency");
    assertThat(project.getArtifacts()).isSameAs(resolvedBefore).containsExactly(used, unused);
    assertThat(project.getDependencyArtifacts())
        .isSameAs(directBefore)
        .containsExactly(used, unused);
  }

  @Test
  void missingTraceFailsWithoutChangingEitherArtifactView()
      throws IOException, ReflectiveOperationException {
    final Artifact used = artifact("used", "used/Sample.class");
    final MavenProject project = project(used, new LinkedHashSet<>(List.of(used)));
    final Set<Artifact> resolvedBefore = project.getArtifacts();
    final Set<Artifact> directBefore = project.getDependencyArtifacts();
    final ElideMojo mojo = newMojo();
    mojo.setLog(new SystemStreamLog());
    set(mojo, "project", project);

    assertThatThrownBy(mojo::execute)
        .isInstanceOf(MojoFailureException.class)
        .hasMessageContaining("At least one supported trace input is required");
    assertThat(project.getArtifacts()).isSameAs(resolvedBefore).containsExactly(used);
    assertThat(project.getDependencyArtifacts()).isSameAs(directBefore).containsExactly(used);
  }

  private MavenProject project(final Artifact resolved, final Set<Artifact> direct) {
    return project(resolved, direct, null);
  }

  private MavenProject project(
      final Artifact resolved, final Set<Artifact> direct, final Artifact additionalResolved) {
    final MavenProject project = newProject();
    final Set<Artifact> artifacts = new LinkedHashSet<>(List.of(resolved));
    if (additionalResolved != null) {
      artifacts.add(additionalResolved);
    }
    project.setArtifacts(artifacts);
    project.setDependencyArtifacts(direct);
    return project;
  }

  private MavenProject newProject() {
    final MavenProject project = new MavenProject();
    project.setFile(tempDir.resolve("pom.xml").toFile());
    project.setGroupId("org.example");
    project.setArtifactId("consumer");
    project.setVersion("1.0");
    project.getProperties().setProperty("maven.compiler.release", "21");
    return project;
  }

  private MavenElisionReportSnapshot previousSnapshot() throws IOException {
    return new MavenElisionReportSnapshot(
        MavenElisionReportSnapshot.SCHEMA_VERSION,
        "org.example",
        "consumer",
        "1.0",
        tempDir.toRealPath().toString(),
        "2026-10-25T12:00:00Z",
        0,
        0,
        List.of(),
        List.of(),
        0,
        0,
        List.of());
  }

  private static void assertLastSuccessfulSnapshotRemains(
      final Path output, final MavenElisionReportSnapshot previous) throws IOException {
    assertThat(MavenElisionReportWriter.read(output)).isEqualTo(previous);
  }

  private void execute(final MavenProject project, final String traceContent)
      throws IOException, ReflectiveOperationException, MojoFailureException {
    execute(project, traceContent, new SystemStreamLog());
  }

  private void execute(final MavenProject project, final String traceContent, final Log log)
      throws IOException, ReflectiveOperationException, MojoFailureException {
    final Path trace = tempDir.resolve("runtime.lst");
    Files.writeString(trace, traceContent);
    final ElideMojo mojo = newMojo();
    mojo.setLog(log);
    set(mojo, "project", project);
    set(mojo, "traceFiles", List.of(trace.toFile()));
    set(mojo, "reportFile", tempDir.resolve("elide-report.json").toFile());
    mojo.execute();
  }

  private static ElideMojo newMojo() {
    final ElideMojo mojo = new ElideMojo();
    final MavenSession session =
        new MavenSession(
            testContainer(),
            new DefaultRepositorySystemSession(),
            new DefaultMavenExecutionRequest(),
            null);
    try {
      set(mojo, "session", session);
    } catch (final ReflectiveOperationException exception) {
      throw new IllegalStateException("Cannot initialize Maven session fixture", exception);
    }
    return mojo;
  }

  @SuppressWarnings("PMD.UseProperClassLoader")
  private static PlexusContainer testContainer() {
    return (PlexusContainer)
        Proxy.newProxyInstance(
            PlexusContainer.class.getClassLoader(),
            new Class<?>[] {PlexusContainer.class},
            (proxy, method, arguments) -> {
              if (LOOKUP_METHOD.equals(method.getName())) {
                return Proxy.newProxyInstance(
                    ToolchainManager.class.getClassLoader(),
                    new Class<?>[] {ToolchainManager.class},
                    (manager, managerMethod, managerArguments) -> null);
              }
              return null;
            });
  }

  private Artifact artifact(final String artifactId, final String classEntry) throws IOException {
    final Artifact artifact =
        new DefaultArtifact(
            "org.example",
            artifactId,
            "1.0",
            "compile",
            "jar",
            null,
            new DefaultArtifactHandler("jar"));
    artifact.setFile(writeJar(artifactId + ".jar", classEntry).toFile());
    return artifact;
  }

  private static long classEntrySize(final Path archivePath, final String entryName)
      throws IOException {
    try (JarFile archive = new JarFile(archivePath.toFile())) {
      return archive.getEntry(entryName).getSize();
    }
  }

  private Path writeJar(final String name, final String classEntry) throws IOException {
    final Path jar = tempDir.resolve(name);
    final String internalName = classEntry.substring(0, classEntry.length() - ".class".length());
    final ClassWriter writer = new ClassWriter(0);
    writer.visit(Opcodes.V21, Opcodes.ACC_PUBLIC, internalName, null, "java/lang/Object", null);
    writer.visitEnd();
    try (ZipOutputStream output = new ZipOutputStream(Files.newOutputStream(jar))) {
      output.putNextEntry(new ZipEntry(classEntry));
      output.write(writer.toByteArray());
      output.closeEntry();
    }
    return jar;
  }

  private static void set(final Object target, final String name, final Object value)
      throws ReflectiveOperationException {
    final Field field = target.getClass().getDeclaredField(name);
    field.setAccessible(true);
    field.set(target, value);
  }

  private void seedResolverPlan(
      final ElideMojo mojo, final MavenProject project, final String outputName)
      throws IOException, ReflectiveOperationException {
    final Path replacement = tempDir.resolve(outputName);
    Files.writeString(replacement, outputName);
    final ResolverArtifactPlan.ProjectIdentity projectIdentity =
        new ResolverArtifactPlan.ProjectIdentity(
            project.getBasedir().toPath(),
            project.getGroupId(),
            project.getArtifactId(),
            project.getVersion());
    final ResolverArtifactPlan plan =
        new ResolverArtifactPlan(
            projectIdentity,
            Map.of(
                new ResolverArtifactPlan.ArtifactIdentity("org.example", "stale", "1.0", "jar", ""),
                new ResolverArtifactPlan.Replacement(
                    replacement, ArtifactFileDigest.sha256(replacement))));
    final MavenSession session = (MavenSession) fieldValue(mojo, "session");
    session
        .getRepositorySession()
        .getData()
        .set(
            ResolverArtifactPlanPublisher.SESSION_DATA_KEY,
            ResolverArtifactPlanStore.empty().withPlan(plan).toPayload());
  }

  private ResolverArtifactPlan resolverPlan(final ElideMojo mojo, final MavenProject project)
      throws ReflectiveOperationException {
    final MavenSession session = (MavenSession) fieldValue(mojo, "session");
    final Object payload =
        session
            .getRepositorySession()
            .getData()
            .get(ResolverArtifactPlanPublisher.SESSION_DATA_KEY);
    return ResolverArtifactPlanStore.fromPayload(payload)
        .find(
            new ResolverArtifactPlan.ProjectIdentity(
                project.getBasedir().toPath(),
                project.getGroupId(),
                project.getArtifactId(),
                project.getVersion()));
  }

  private static Object fieldValue(final Object target, final String name)
      throws ReflectiveOperationException {
    final Field field = target.getClass().getDeclaredField(name);
    field.setAccessible(true);
    return field.get(target);
  }
}
