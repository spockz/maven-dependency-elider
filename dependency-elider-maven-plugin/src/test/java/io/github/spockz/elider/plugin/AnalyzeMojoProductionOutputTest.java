/*
 * WHY: Keeps production output checks separate from artifact adaptation.
 */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertTrue;

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
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

/** Tests production output. JUnit supplies its implicit constructor. */
@SuppressWarnings("PMD.AtLeastOneConstructor")
final class AnalyzeMojoProductionOutputTest {
  /** Class name used for the unused artifact fixture. */
  private static final String UNUSED_CLASS = "unused.Idle";

  /** Maven packaging type used for generated test artifacts. */
  private static final String JAR_TYPE = "jar";

  /** Bytecode root shared by the fixture classes. */
  private static final String OBJECT_TYPE = "java/lang/Object";

  /** Destination for class-usage evidence. */
  private static final String REPORT_FIELD = "reportFile";

  /** Analyze mojo field that selects the production class directory. */
  private static final String PRODUCTION_OUTPUT_FIELD = "productionOutput";

  /** Analyze mojo field for the current project. */
  private static final String PROJECT_FIELD = "project";

  /** Analyze mojo field for recorded class loads. */
  private static final String TRACE_FILES_FIELD = "traceFiles";

  /** Analyze mojo field for the production completeness assertion. */
  private static final String COMPLETENESS_FIELD = "productionClassesComplete";

  /** Maven property identifying the target feature release. */
  private static final String COMPILER_RELEASE = "maven.compiler.release";

  /** Maven artifact version used by output scenarios. */
  private static final String VERSION = "1.0";

  /** Dependency scope used for compile-visible artifacts. */
  private static final String COMPILE_SCOPE = "compile";

  /** Holds generated projects, classes, traces, and reports. */
  @TempDir private Path tempDir;

  @Test
  void reportsRuntimeAndProjectPoliciesWithoutDependencyCandidates() throws Exception {
    final MavenProject project = AnalyzeMojoTestArtifactSupport.project(tempDir, "project-policy");
    project.setGroupId("org.example");
    project.setArtifactId("app");
    project.setVersion("2.0");
    project
        .getProperties()
        .setProperty(COMPILER_RELEASE, Integer.toString(Runtime.version().feature() - 1));
    final Path output = Files.createDirectories(tempDir.resolve("project-policy/classes"));
    final Build build = new Build();
    build.setDirectory(output.getParent().toString());
    build.setOutputDirectory(output.toString());
    final Path testOutput = output.resolveSibling("test-classes");
    build.setTestOutputDirectory(testOutput.toString());
    project.setBuild(build);
    final Path trace = tempDir.resolve("project-policy-trace.lst");
    Files.writeString(trace, "app/Parser\n");
    final Path classFile = output.resolve("app/Parser.class");
    Files.createDirectories(classFile.getParent());
    final ClassWriter writer = new ClassWriter(0);
    writer.visit(Opcodes.V21, Opcodes.ACC_PUBLIC, "app/Parser", null, OBJECT_TYPE, null);
    writer.visitEnd();
    Files.write(classFile, writer.toByteArray());
    final Path testClass = testOutput.resolve("app/Missing.class");
    Files.createDirectories(testClass.getParent());
    final ClassWriter testWriter = new ClassWriter(0);
    testWriter.visit(Opcodes.V21, Opcodes.ACC_PUBLIC, "app/Missing", null, OBJECT_TYPE, null);
    testWriter.visitEnd();
    Files.write(testClass, testWriter.toByteArray());
    final Path summary = tempDir.resolve("policy-analysis.json");
    final AnalyzeMojo mojo = new AnalyzeMojo();
    AnalyzeMojoTestFieldSupport.installLegacyPredictionFixture(mojo);
    AnalyzeMojoTestFieldSupport.set(mojo, PROJECT_FIELD, project);
    AnalyzeMojoTestFieldSupport.set(mojo, TRACE_FILES_FIELD, List.of(trace.toFile()));
    AnalyzeMojoTestFieldSupport.set(mojo, COMPLETENESS_FIELD, true);
    AnalyzeMojoTestFieldSupport.set(mojo, "analysisSummaryFile", summary.toFile());
    AnalyzeMojoTestFieldSupport.set(
        mojo, REPORT_FIELD, tempDir.resolve("policy-class-usage.json").toFile());
    AnalyzeMojoTestFieldSupport.set(
        mojo, "cveCacheDirectory", tempDir.resolve("policy-advisory-cache").toFile());
    final VulnerabilityMappingConfig projectRule =
        VulnerabilityMappingPlexusBindingTest.bind(
            """
            <vulnerabilityMapping><cveId>CVE-2026-10001</cveId>
              <componentKind>PROJECT_OUTPUT</componentKind><version>2.0</version>
              <forbiddenSymbols><symbol>app.Parser</symbol><symbol>app.Missing</symbol></forbiddenSymbols>
            </vulnerabilityMapping>
            """);
    final VulnerabilityMappingConfig runtimeRule =
        VulnerabilityMappingPlexusBindingTest.bind(
            """
            <vulnerabilityMapping><cveId>CVE-2026-10002</cveId>
              <componentKind>JAVA_RUNTIME</componentKind><versionRangeSpec>(,)</versionRangeSpec>
              <forbiddenSymbols><symbol>java.lang.System#gc()</symbol></forbiddenSymbols>
            </vulnerabilityMapping>
            """);
    AnalyzeMojoTestFieldSupport.set(
        mojo, "vulnerabilityMappings", List.of(projectRule, runtimeRule));
    mojo.execute();
    final MavenElisionReportSnapshot saved = MavenElisionReportWriter.read(summary);
    assertAll(
        "prediction separates independently scoped results",
        () ->
            assertThat(saved.forbiddenCodeAssessments())
                .extracting(ForbiddenCodeAssessment::status)
                .containsExactlyInAnyOrder(
                    ForbiddenCodeAssessment.Status.PASS,
                    ForbiddenCodeAssessment.Status.VIOLATION,
                    ForbiddenCodeAssessment.Status.UNKNOWN),
        () ->
            assertThat(saved.forbiddenCodeAssessments())
                .extracting(ForbiddenCodeAssessment::mode)
                .containsOnly(ForbiddenCodeAssessment.Mode.PREDICTED),
        () -> assertTrue(Files.isRegularFile(classFile), "Analysis preserves compiled classes"));
    AnalyzeMojoTestFieldSupport.set(mojo, "failOnForbiddenCode", true);
    assertThatThrownBy(mojo::execute)
        .isInstanceOf(MojoFailureException.class)
        .hasMessageContaining("Forbidden code");

    projectRule.setForbiddenSymbols(List.of("app.Missing"));
    AnalyzeMojoTestFieldSupport.set(mojo, COMPLETENESS_FIELD, false);
    mojo.execute();
    final MavenElisionReportSnapshot incomplete = MavenElisionReportWriter.read(summary);
    assertThat(incomplete.forbiddenCodeAssessments())
        .as("enforcement permits unknown outcomes for incomplete direct invocations")
        .extracting(ForbiddenCodeAssessment::status)
        .containsExactly(
            ForbiddenCodeAssessment.Status.UNKNOWN, ForbiddenCodeAssessment.Status.UNKNOWN);
  }

  @Test
  void exactRuntimeCallFailsAnalysisWithPersistedCallSiteEvidence() throws Exception {
    final MavenProject project = AnalyzeMojoTestArtifactSupport.project(tempDir, "runtime-call");
    project
        .getProperties()
        .setProperty(COMPILER_RELEASE, Integer.toString(Runtime.version().feature()));
    final Path output = tempDir.resolve("runtime-production");
    final Path tests = tempDir.resolve("test-classes");
    writeDecoderCall(output, "app/Production", "([B)[B");
    writeDecoderCall(tests, "app/TestOnly", "(Ljava/lang/String;)[B");
    final Build build = new Build();
    build.setDirectory(tempDir.toString());
    build.setOutputDirectory(output.toString());
    build.setTestOutputDirectory(tests.toString());
    project.setBuild(build);
    final Path trace = tempDir.resolve("runtime-trace.lst");
    Files.writeString(trace, "app/Production\n");
    final Path summary = tempDir.resolve("runtime-policy.json");
    final AnalyzeMojo mojo = ExplicitRuntimeMojoTestSupport.newAnalyzeMojo();
    AnalyzeMojoTestFieldSupport.installLegacyPredictionFixture(mojo);
    AnalyzeMojoTestFieldSupport.set(mojo, PROJECT_FIELD, project);
    AnalyzeMojoTestFieldSupport.set(mojo, TRACE_FILES_FIELD, List.of(trace.toFile()));
    AnalyzeMojoTestFieldSupport.set(mojo, COMPLETENESS_FIELD, true);
    AnalyzeMojoTestFieldSupport.set(mojo, "failOnForbiddenCode", true);
    AnalyzeMojoTestFieldSupport.set(mojo, "analysisSummaryFile", summary.toFile());
    AnalyzeMojoTestFieldSupport.set(
        mojo, REPORT_FIELD, tempDir.resolve("runtime-classes.json").toFile());
    AnalyzeMojoTestFieldSupport.set(
        mojo, "cveCacheDirectory", tempDir.resolve("runtime-advisories").toFile());
    final VulnerabilityMappingConfig runtimeRule =
        VulnerabilityMappingPlexusBindingTest.bind(
            """
            <vulnerabilityMapping><cveId>CVE-2026-10002</cveId>
              <componentKind>JAVA_RUNTIME</componentKind><versionRangeSpec>(,)</versionRangeSpec>
              <forbiddenSymbols>
                <symbol>java.util.Base64.Decoder#decode(byte[])</symbol>
                <symbol>java.util.Base64.Decoder#decode(java.lang.String)</symbol>
                <symbol>java.util.Base64.Decoder</symbol>
              </forbiddenSymbols>
            </vulnerabilityMapping>
            """);
    final VulnerabilityMappingConfig outsideVersion = new VulnerabilityMappingConfig();
    outsideVersion.setCveId("CVE-2026-10003");
    outsideVersion.setComponentKind(ForbiddenCodeAssessment.ComponentKind.JAVA_RUNTIME);
    outsideVersion.setVersion("8");
    outsideVersion.setForbiddenSymbols(List.of("java.util.Base64.Decoder#decode(byte[])"));
    AnalyzeMojoTestFieldSupport.set(
        mojo, "vulnerabilityMappings", List.of(runtimeRule, outsideVersion));

    assertThatThrownBy(mojo::execute)
        .isInstanceOf(MojoFailureException.class)
        .hasMessageContaining("1 violation");
    final List<ForbiddenCodeAssessment> results =
        MavenElisionReportWriter.read(summary).forbiddenCodeAssessments();
    assertAll(
        () ->
            assertThat(results)
                .extracting(ForbiddenCodeAssessment::mode)
                .containsOnly(ForbiddenCodeAssessment.Mode.PREDICTED),
        () ->
            assertThat(results)
                .filteredOn(row -> "CVE-2026-10003".equals(row.cveId()))
                .extracting(ForbiddenCodeAssessment::status)
                .containsExactly(ForbiddenCodeAssessment.Status.NOT_APPLICABLE),
        () ->
            assertThat(results)
                .filteredOn(row -> row.status() == ForbiddenCodeAssessment.Status.UNKNOWN)
                .extracting(ForbiddenCodeAssessment::symbol)
                .containsExactlyInAnyOrder(
                    "java.util.Base64.Decoder",
                    "java.util.Base64.Decoder#decode(java.lang.String)"),
        () ->
            assertThat(results)
                .filteredOn(row -> row.status() == ForbiddenCodeAssessment.Status.VIOLATION)
                .singleElement()
                .satisfies(
                    result ->
                        assertAll(
                            () ->
                                assertThat(result.evidenceKind()).isEqualTo("DIRECT_RUNTIME_CALL"),
                            () ->
                                assertThat(result.matches())
                                    .containsExactly(
                                        new ForbiddenCodeAssessment.Match(
                                            output.toString(),
                                            "app/Production.class",
                                            0,
                                            "java.util.Base64$Decoder",
                                            List.of("([B)[B"))),
                            () -> assertThat(result.assertsAffected()).isFalse())));

    final int foreignTarget = Runtime.version().feature() - 1;
    project.getProperties().setProperty(COMPILER_RELEASE, Integer.toString(foreignTarget));
    AnalyzeMojoTestFieldSupport.set(mojo, "runtimeInputs", List.of());
    assertThatThrownBy(mojo::execute)
        .isInstanceOf(MojoFailureException.class)
        .hasMessageContaining("2 violation");
    final List<ForbiddenCodeAssessment> withoutRuntime =
        MavenElisionReportWriter.read(summary).forbiddenCodeAssessments();
    assertAll(
        () ->
            assertThat(withoutRuntime)
                .filteredOn(row -> row.status() == ForbiddenCodeAssessment.Status.VIOLATION)
                .hasSize(2)
                .allSatisfy(
                    row ->
                        assertAll(
                            () -> assertThat(row.componentIdentity()).isNull(),
                            () -> assertThat(row.componentVersion()).isNull(),
                            () -> assertThat(row.targetRelease()).isEqualTo(foreignTarget),
                            () ->
                                assertThat(row.versionApplicability())
                                    .isEqualTo(
                                        ForbiddenCodeAssessment.VersionApplicability.UNKNOWN),
                            () -> assertThat(row.reason()).contains("No inspected Java runtime"))),
        () ->
            assertThat(withoutRuntime)
                .filteredOn(row -> row.status() == ForbiddenCodeAssessment.Status.UNKNOWN)
                .hasSize(2));
  }

  private static void writeDecoderCall(final Path root, final String name, final String descriptor)
      throws IOException {
    final ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_MAXS);
    writer.visit(Opcodes.V21, Opcodes.ACC_PUBLIC, name, null, OBJECT_TYPE, null);
    writer.visitInnerClass(
        "java/util/Base64$Decoder",
        "java/util/Base64",
        "Decoder",
        Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC);
    final MethodVisitor method =
        writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "run", "()V", null, null);
    method.visitCode();
    method.visitMethodInsn(
        Opcodes.INVOKESTATIC,
        "java/util/Base64",
        "getDecoder",
        "()Ljava/util/Base64$Decoder;",
        false);
    method.visitInsn(Opcodes.ACONST_NULL);
    method.visitMethodInsn(
        Opcodes.INVOKEVIRTUAL, "java/util/Base64$Decoder", "decode", descriptor, false);
    method.visitInsn(Opcodes.POP);
    method.visitInsn(Opcodes.RETURN);
    method.visitMaxs(0, 0);
    method.visitEnd();
    writer.visitEnd();
    final Path file = root.resolve(name + ".class");
    Files.createDirectories(file.getParent());
    Files.write(file, writer.toByteArray());
  }

  @Test
  @DisplayName("ADR-0010/analyze uses configured bytecode output and reports compile savings")
  // WHY: One execution proves output resolution and report evidence together.
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
    final MavenProject project =
        AnalyzeMojoTestArtifactSupport.project(tempDir, "bytecode-default-output");
    project.setArtifacts(new LinkedHashSet<>(List.of(used, unused)));
    project.getProperties().setProperty(COMPILER_RELEASE, "21");
    final Build build = new Build();
    final Path target = tempDir.resolve("bytecode-default-output");
    final Path output = target.resolve("classes");
    build.setDirectory(target.toString());
    build.setOutputDirectory(output.toString());
    project.setBuild(build);
    final Path applicationClass = output.resolve("app/Main.class");
    Files.createDirectories(applicationClass.getParent());
    final ClassWriter writer = new ClassWriter(0);
    writer.visit(Opcodes.V21, Opcodes.ACC_PUBLIC, "app/Main", null, OBJECT_TYPE, null);
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
    AnalyzeMojoTestFieldSupport.set(mojo, PROJECT_FIELD, project);
    AnalyzeMojoTestFieldSupport.installLegacyPredictionFixture(mojo);
    AnalyzeMojoTestFieldSupport.set(mojo, PRODUCTION_OUTPUT_FIELD, output.toFile());
    AnalyzeMojoTestFieldSupport.set(mojo, TRACE_FILES_FIELD, List.of(trace.toFile()));
    AnalyzeMojoTestFieldSupport.set(mojo, COMPLETENESS_FIELD, true);
    AnalyzeMojoTestFieldSupport.set(mojo, REPORT_FIELD, report.toFile());
    AnalyzeMojoTestFieldSupport.set(
        mojo, "cveCacheDirectory", tempDir.resolve("bytecode-analysis-cache").toFile());
    final VulnerabilityMappingConfig mapping = new VulnerabilityMappingConfig();
    mapping.setCveId("CVE-2026-19003");
    mapping.setGroupId("org.example");
    mapping.setArtifactId("unused-compile");
    mapping.setVersion(VERSION);
    mapping.setAssertsAffected(true);
    mapping.setVulnerableClasses(List.of(UNUSED_CLASS));
    AnalyzeMojoTestFieldSupport.set(mojo, "vulnerabilityMappings", List.of(mapping));
    final RecordingMavenLog log = new RecordingMavenLog();
    mojo.setLog(log);

    mojo.execute();

    assertThat(report).isRegularFile();
    assertThat(log.messages())
        .satisfies(
            messages ->
                assertAll(
                    "analysis output keeps planned findings conditional",
                    () ->
                        assertThat(messages)
                            .anyMatch(
                                line ->
                                    line.startsWith(
                                        "Whole artifacts that would be dropped: 0 / 2 ")),
                    () ->
                        assertThat(messages)
                            .anyMatch(
                                line ->
                                    "Raw trace decision drops before graph safety: 1".equals(line)),
                    () ->
                        assertThat(messages)
                            .anyMatch(
                                line ->
                                    "Analysis only: no trim proof or published changes"
                                        .equals(line)),
                    () ->
                        assertThat(messages)
                            .anyMatch(line -> "Vulnerability findings: 1".equals(line)),
                    () ->
                        assertThat(messages)
                            .anyMatch(
                                line ->
                                    line.contains(
                                            "CVE-2026-19003 org.example:unused-compile:jar:1.0")
                                        && line.contains("[RETAINED_UNCHANGED]")),
                    () ->
                        assertThat(messages)
                            .anyMatch(
                                line ->
                                    line.contains("Applicability: AFFECTED; intent: AUTO_VERIFY")),
                    () ->
                        assertThat(messages).anyMatch(line -> line.contains("Outcome: NO_PROOF;")),
                    () -> assertThat(messages).anyMatch(line -> "CVE Sources:".equals(line)),
                    () ->
                        assertThat(messages).anyMatch(line -> line.contains("CACHE UNAVAILABLE"))));
    final com.fasterxml.jackson.databind.JsonNode reportJson =
        new com.fasterxml.jackson.databind.ObjectMapper().readTree(report.toFile());
    assertThat(reportJson.path(PRODUCTION_OUTPUT_FIELD).asText()).isEqualTo(output.toString());
    assertThat(reportJson.path("staticEvidenceAvailable").asBoolean()).isTrue();
    assertThat(reportJson.path("classFilesScanned").asInt()).isEqualTo(1);
    assertThat(reportJson.path("dependencyPrediction").path("wouldElideArtifacts")).isEmpty();
    assertThat(reportJson.path("dependencyPrediction").path("plannedClassRemovals")).isEmpty();
  }

  @Test
  // WHY: One report proves stable serialization and complete evidence.
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
    final MavenProject project = AnalyzeMojoTestArtifactSupport.project(tempDir, "complete-output");
    project.setArtifacts(new LinkedHashSet<>(List.of(used, runtimeOnly, unused)));
    final Path trace = tempDir.resolve("complete.lst");
    Files.writeString(trace, "used/Sample\nruntimeOnly/Type\n");
    final Path productionOutput = Files.createDirectories(tempDir.resolve("classes"));
    final ClassWriter writer = new ClassWriter(0);
    writer.visit(Opcodes.V21, Opcodes.ACC_PUBLIC, "app/Main", null, OBJECT_TYPE, null);
    writer.visitField(Opcodes.ACC_PRIVATE, "used", "Lused/Sample;", null, null).visitEnd();
    writer.visitEnd();
    Files.createDirectories(productionOutput.resolve("app"));
    Files.write(productionOutput.resolve("app/Main.class"), writer.toByteArray());
    final Path report = tempDir.resolve("complete-report.json");
    final AnalyzeMojo mojo = new AnalyzeMojo();
    AnalyzeMojoTestFieldSupport.set(mojo, PROJECT_FIELD, project);
    AnalyzeMojoTestFieldSupport.installLegacyPredictionFixture(mojo);
    AnalyzeMojoTestFieldSupport.set(mojo, TRACE_FILES_FIELD, List.of(trace.toFile()));
    AnalyzeMojoTestFieldSupport.set(mojo, PRODUCTION_OUTPUT_FIELD, productionOutput.toFile());
    AnalyzeMojoTestFieldSupport.set(mojo, REPORT_FIELD, report.toFile());

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
  void rejectsInvalidClassOutputWithoutWritingReport()
      throws IOException, ReflectiveOperationException {
    final AnalyzeMojoTestArtifactSupport.Fixture fixture =
        AnalyzeMojoTestArtifactSupport.fixture(tempDir, "used/Sample\n");
    final Path report = tempDir.resolve("invalid-scan.json");
    final AnalyzeMojo mojo = fixture.mojo();
    AnalyzeMojoTestFieldSupport.installLegacyPredictionFixture(mojo);
    final Path invalidOutput = tempDir.resolve("not-a-class-directory");
    Files.writeString(invalidOutput, "not a directory");
    AnalyzeMojoTestFieldSupport.set(mojo, PRODUCTION_OUTPUT_FIELD, invalidOutput.toFile());
    AnalyzeMojoTestFieldSupport.set(mojo, REPORT_FIELD, report.toFile());

    assertThatThrownBy(mojo::execute)
        .isInstanceOf(MojoFailureException.class)
        .hasMessageContaining("Production class output path is not a directory");
    assertThat(report).doesNotExist();
  }
}
