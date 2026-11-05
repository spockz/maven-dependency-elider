/*
 * WHY: Keeps production output checks separate from artifact adaptation.
 */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashSet;
import java.util.List;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.model.Build;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.project.MavenProject;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;

/** Tests production output. JUnit supplies its implicit constructor. */
@SuppressWarnings("PMD.AtLeastOneConstructor")
final class AnalyzeMojoProductionOutputTest {
  /** Class name used for the unused artifact fixture. */
  private static final String UNUSED_CLASS = "unused.Idle";

  /** Maven packaging type used for generated test artifacts. */
  private static final String JAR_TYPE = "jar";

  /** Analyze mojo field that selects the production class directory. */
  private static final String PRODUCTION_OUTPUT_FIELD = "productionOutput";

  /** Maven artifact version used by output scenarios. */
  private static final String VERSION = "1.0";

  /** Dependency scope used for compile-visible artifacts. */
  private static final String COMPILE_SCOPE = "compile";

  /** Holds generated projects, classes, traces, and reports. */
  @TempDir private Path tempDir;

  @Test
  @DisplayName("ADR-0010/analyze uses configured bytecode output and reports compile savings")
  // WHY: One execution proves output resolution and report evidence together.
  @SuppressWarnings("PMD.UnitTestContainsTooManyAsserts")
  void productionClassesCompleteUsesConfiguredOutputAndReportsCompileCveSavings()
      throws IOException, ReflectiveOperationException, MojoFailureException {
    final Artifact used =
        AnalyzeMojoTestArtifactSupport.artifact(
            tempDir,
            "used-bytecode",
            VERSION,
            COMPILE_SCOPE,
            JAR_TYPE,
            "used-bytecode.jar",
            "used/Sample.class");
    final Artifact unused =
        AnalyzeMojoTestArtifactSupport.artifact(
            tempDir,
            "unused-compile",
            VERSION,
            COMPILE_SCOPE,
            JAR_TYPE,
            "unused-compile.jar",
            "unused/Idle.class");
    final MavenProject project = new MavenProject();
    project.setArtifacts(new LinkedHashSet<>(List.of(used, unused)));
    project.getProperties().setProperty("maven.compiler.release", "21");
    final Build build = new Build();
    final Path target = tempDir.resolve("bytecode-default-output");
    final Path output = target.resolve("classes");
    build.setDirectory(target.toString());
    build.setOutputDirectory(output.toString());
    project.setBuild(build);
    final Path applicationClass = output.resolve("app/Main.class");
    Files.createDirectories(applicationClass.getParent());
    final ClassWriter writer = new ClassWriter(0);
    writer.visit(Opcodes.V21, Opcodes.ACC_PUBLIC, "app/Main", null, "java/lang/Object", null);
    writer.visitField(Opcodes.ACC_PRIVATE, "used", "Lused/Sample;", null, null).visitEnd();
    writer.visitEnd();
    Files.write(applicationClass, writer.toByteArray());
    final Path sourceRoot = Files.createDirectories(target.resolve("source-root"));
    final Path applicationSource = sourceRoot.resolve("app/Main.java");
    Files.createDirectories(applicationSource.getParent());
    Files.writeString(
        applicationSource, "package app; public final class Main { used.Sample value; }\n");
    project.addCompileSourceRoot(sourceRoot.toString());
    final Path trace = tempDir.resolve("bytecode-default-output.lst");
    Files.writeString(trace, "used/Sample\n");
    final Path report = target.resolve("dependency-elider-class-usage.json");
    final AnalyzeMojo mojo = new AnalyzeMojo();
    AnalyzeMojoTestFieldSupport.set(mojo, "project", project);
    AnalyzeMojoTestFieldSupport.installLegacyPredictionFixture(mojo);
    AnalyzeMojoTestFieldSupport.set(mojo, PRODUCTION_OUTPUT_FIELD, output.toFile());
    AnalyzeMojoTestFieldSupport.set(mojo, "traceFiles", List.of(trace.toFile()));
    AnalyzeMojoTestFieldSupport.set(mojo, "productionClassesComplete", true);
    AnalyzeMojoTestFieldSupport.set(mojo, "reportFile", report.toFile());
    AnalyzeMojoTestFieldSupport.set(
        mojo, "cveCacheDirectory", tempDir.resolve("bytecode-analysis-cache").toFile());
    final VulnerabilityMappingConfig mapping = new VulnerabilityMappingConfig();
    mapping.setCveId("CVE-2026-19003");
    mapping.setGroupId("org.example");
    mapping.setArtifactId("unused-compile");
    mapping.setVersion(VERSION);
    mapping.setVulnerableClasses(List.of(UNUSED_CLASS));
    AnalyzeMojoTestFieldSupport.set(mojo, "vulnerabilityMappings", List.of(mapping));
    final RecordingMavenLog log = new RecordingMavenLog();
    mojo.setLog(log);

    mojo.execute();

    assertThat(report).isRegularFile();
    assertThat(log.messages())
        .contains(
            "  Artifacts that would be elided by this analysis: 1 / 2 (50.0%)",
            "    CVE-2026-19003 org.example:unused-compile:jar:1.0: "
                + "AFFECTED; UNVERIFIED; PLANNED_UNVERIFIED");
    final com.fasterxml.jackson.databind.JsonNode reportJson =
        new com.fasterxml.jackson.databind.ObjectMapper().readTree(report.toFile());
    assertThat(reportJson.path(PRODUCTION_OUTPUT_FIELD).asText()).isEqualTo(output.toString());
    assertThat(reportJson.path("staticEvidenceAvailable").asBoolean()).isTrue();
    assertThat(reportJson.path("classFilesScanned").asInt()).isEqualTo(1);
  }

  @Test
  // WHY: One report proves stable serialization and complete evidence.
  @SuppressWarnings("PMD.UnitTestContainsTooManyAsserts")
  void writesCompleteStaticGroupsAndDeterministicClassNames()
      throws IOException, ReflectiveOperationException, MojoFailureException {
    final Artifact used =
        AnalyzeMojoTestArtifactSupport.artifact(
            tempDir, "used", VERSION, COMPILE_SCOPE, JAR_TYPE, "used.jar", "used/Sample.class");
    final Artifact runtimeOnly =
        AnalyzeMojoTestArtifactSupport.artifact(
            tempDir,
            "runtime-only",
            VERSION,
            COMPILE_SCOPE,
            JAR_TYPE,
            "runtime-only.jar",
            "runtimeOnly/Type.class");
    final Artifact unused =
        AnalyzeMojoTestArtifactSupport.artifact(
            tempDir, "unused", VERSION, COMPILE_SCOPE, JAR_TYPE, "unused.jar", "unused/Idle.class");
    final MavenProject project = new MavenProject();
    project.setArtifacts(new LinkedHashSet<>(List.of(used, runtimeOnly, unused)));
    final Path trace = tempDir.resolve("complete.lst");
    Files.writeString(trace, "used/Sample\nruntimeOnly/Type\n");
    final Path productionOutput = Files.createDirectories(tempDir.resolve("classes"));
    final ClassWriter writer = new ClassWriter(0);
    writer.visit(Opcodes.V21, Opcodes.ACC_PUBLIC, "app/Main", null, "java/lang/Object", null);
    writer.visitField(Opcodes.ACC_PRIVATE, "used", "Lused/Sample;", null, null).visitEnd();
    writer.visitEnd();
    Files.createDirectories(productionOutput.resolve("app"));
    Files.write(productionOutput.resolve("app/Main.class"), writer.toByteArray());
    final Path report = tempDir.resolve("complete-report.json");
    final AnalyzeMojo mojo = new AnalyzeMojo();
    AnalyzeMojoTestFieldSupport.set(mojo, "project", project);
    AnalyzeMojoTestFieldSupport.installLegacyPredictionFixture(mojo);
    AnalyzeMojoTestFieldSupport.set(mojo, "traceFiles", List.of(trace.toFile()));
    AnalyzeMojoTestFieldSupport.set(mojo, PRODUCTION_OUTPUT_FIELD, productionOutput.toFile());
    AnalyzeMojoTestFieldSupport.set(mojo, "reportFile", report.toFile());

    mojo.execute();
    final String firstOutput = Files.readString(report);
    mojo.execute();

    assertThat(Files.readString(report)).isEqualTo(firstOutput);
    final com.fasterxml.jackson.databind.JsonNode json =
        new com.fasterxml.jackson.databind.ObjectMapper().readTree(firstOutput);
    assertThat(json.path("staticEvidenceAvailable").asBoolean()).isTrue();
    assertThat(json.path("classFilesScanned").asInt()).isEqualTo(1);
    assertThat(json.path("groups").path("applicationReferenced").toString())
        .contains("used.Sample");
    assertThat(json.path("groups").path("runtimeObservedWithoutApplicationReference").toString())
        .contains("runtimeOnly.Type");
    assertThat(json.path("groups").path("neitherReferencedNorObserved").toString())
        .contains(UNUSED_CLASS);
    assertThat(json.path("classes").toString())
        .contains("used.Sample", "runtimeOnly.Type", UNUSED_CLASS);
  }

  @Test
  // WHY: Rejection and an unpublished report prove the output boundary.
  @SuppressWarnings("PMD.UnitTestContainsTooManyAsserts")
  void rejectsInvalidClassOutputWithoutWritingReport()
      throws IOException, ReflectiveOperationException {
    final AnalyzeMojoTestArtifactSupport.Fixture fixture =
        AnalyzeMojoTestArtifactSupport.fixture(tempDir, "used/Sample\n");
    final Path report = tempDir.resolve("invalid-scan.json");
    final AnalyzeMojo mojo = fixture.mojo();
    AnalyzeMojoTestFieldSupport.installLegacyPredictionFixture(mojo);
    AnalyzeMojoTestFieldSupport.set(
        mojo, PRODUCTION_OUTPUT_FIELD, tempDir.resolve("missing-classes").toFile());
    AnalyzeMojoTestFieldSupport.set(mojo, "reportFile", report.toFile());

    assertThatThrownBy(mojo::execute)
        .isInstanceOf(MojoFailureException.class)
        .hasMessageContaining("Production class output directory is missing");
    assertThat(report).doesNotExist();
  }
}
