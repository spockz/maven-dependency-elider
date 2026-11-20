/* WHY: Exercises per-runtime decisions, publication, and replacement with a real reduced image. */

package io.github.spockz.elider.plugin;

import static io.github.spockz.elider.plugin.AnalyzeMojoTestFieldSupport.set;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import java.util.spi.ToolProvider;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.execution.DefaultMavenExecutionRequest;
import org.apache.maven.execution.DefaultMavenExecutionResult;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.project.MavenProject;
import org.codehaus.plexus.DefaultPlexusContainer;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.ModuleVisitor;
import org.objectweb.asm.Opcodes;

@SuppressWarnings({"PMD.AtLeastOneConstructor", "PMD.CommentRequired"})
final class RuntimeSelectionGoalsTest {
  private static final String SQL_CLASS = "java.sql.DriverManager";
  private static final String SQL_SUPERCLASS = "java.sql.SQLException";
  private static final String ADAPTER = "fixture/Adapter";
  private static final String SIBLING = "fixture/Sibling";
  private static final String UNUSED = "fixture/Unused";
  private static final String OBSERVED_JSON = "observed.json";
  private static final String SUMMARY_FILE = "summaryFile";
  private static final String OBJECT = "java/lang/Object";
  private static final String RUNNABLE = "java/lang/Runnable";
  private static final String NO_ARGS_VOID_DESCRIPTOR = "()V";
  private static final String HOST = System.getProperty("java.home");
  private static final String RELEASE = "release";
  private static final String MODULE_IMAGE = "lib/modules";
  private static final String MODULE_INFO = "module-info.class";
  private static final String MISSING_MODULE = "fixture.deployment";
  @TempDir private static Path shared;
  @TempDir private Path work;

  @BeforeAll
  static void createReducedImage() {
    final java.util.Optional<ToolProvider> jlink = ToolProvider.findFirst("jlink");
    org.junit.jupiter.api.Assumptions.assumeTrue(
        jlink.isPresent(), "A reduced image fixture requires jlink");
    final StringWriter log = new StringWriter();
    final PrintWriter output = new PrintWriter(log);
    assertThat(
            jlink
                .orElseThrow()
                .run(
                    output,
                    output,
                    "--add-modules",
                    "java.base",
                    "--strip-debug",
                    "--output",
                    reduced().toString()))
        .as(log.toString())
        .isZero();
  }

  @Test
  void reopensAnImageAfterReplacementInTheSameMavenSession() throws IOException {
    final MavenSession session =
        new MavenSession(
            null, null, new DefaultMavenExecutionRequest(), new DefaultMavenExecutionResult());
    final Path image = Files.createDirectory(work.resolve("mutable"));
    Files.createDirectory(image.resolve("lib"));
    Files.copy(reduced().resolve(RELEASE), image.resolve(RELEASE));
    final Path modules = image.resolve(MODULE_IMAGE);
    Files.copy(reduced().resolve(MODULE_IMAGE), modules);
    final List<String> configured = List.of(image.toString());
    final MavenRuntimePlatforms valid = MavenRuntimePlatforms.inspect(work, configured, session);
    Files.writeString(modules, "corrupted fixture");
    final MavenRuntimePlatforms broken = MavenRuntimePlatforms.inspect(work, configured, session);
    Files.copy(
        reduced().resolve(MODULE_IMAGE),
        modules,
        java.nio.file.StandardCopyOption.REPLACE_EXISTING);
    final MavenRuntimePlatforms restored = MavenRuntimePlatforms.inspect(work, configured, session);
    assertAll(
        () ->
            org.junit.jupiter.api.Assertions.assertTrue(
                valid.hasLinkage(), "The initial runtime must be usable before replacement"),
        () ->
            org.junit.jupiter.api.Assertions.assertFalse(
                broken.hasLinkage(),
                "Replacing bytes at the same path must invalidate the old view"),
        () -> assertThat(broken.inputs().getFirst().problem()).contains(image.toString()),
        () -> assertThat(restored.fingerprint()).isEqualTo(valid.fingerprint()));
  }

  @Test
  void rejectsBrokenProductionViewsAndPreservesPreviousGoalReports() throws Exception {
    final MavenProject project = ExplicitRuntimeMojoTestSupport.project(work);
    writeApplication(
        project,
        method -> {
          method.visitMethodInsn(
              Opcodes.INVOKESTATIC, "java/sql/DriverManager", "getLoginTimeout", "()I", false);
          method.visitInsn(Opcodes.POP);
        });
    final AnalyzeMojo analyze = ExplicitRuntimeMojoTestSupport.newAnalyzeMojo();
    AnalyzeMojoTestFieldSupport.installLegacyPredictionFixture(analyze);
    final Path prediction = work.resolve("prediction.json");
    set(analyze, "analysisSummaryFile", prediction.toFile());
    ExplicitRuntimeMojoTestSupport.configure(analyze, project, work, List.of(HOST));
    final ElideMojo elide = ExplicitRuntimeMojoTestSupport.newElideMojo();
    final Path observed = work.resolve(OBSERVED_JSON);
    set(elide, SUMMARY_FILE, observed.toFile());
    ExplicitRuntimeMojoTestSupport.configure(elide, project, work, List.of(HOST));
    analyze.execute();
    elide.execute();
    final byte[] previousPrediction = Files.readAllBytes(prediction);
    final byte[] previousObserved = Files.readAllBytes(observed);
    set(analyze, "runtimeInputs", List.of(reduced().toString(), HOST));
    set(elide, "runtimeInputs", List.of(HOST, reduced().toString()));
    assertAll(
        () ->
            assertThatThrownBy(analyze::execute)
                .isInstanceOf(MojoFailureException.class)
                .hasMessageContaining(SQL_CLASS),
        () ->
            assertThatThrownBy(elide::execute)
                .isInstanceOf(MojoFailureException.class)
                .hasMessageContaining(SQL_CLASS),
        () -> assertThat(Files.readAllBytes(prediction)).isEqualTo(previousPrediction),
        () -> assertThat(Files.readAllBytes(observed)).isEqualTo(previousObserved));
  }

  @ParameterizedTest(name = "production uses a proven service provider = {0}")
  @org.junit.jupiter.params.provider.ValueSource(booleans = {false, true})
  @SuppressWarnings("PMD.LawOfDemeter") // Maven exposes the published artifact path through File.
  void rejectsMissingSuperclassOfPassThroughDependencyBeforePublishing(final boolean service)
      throws Exception {
    final MavenProject project = ExplicitRuntimeMojoTestSupport.project(work);
    final String needed = SIBLING;
    writeApplication(
        project,
        method -> {
          if (service) {
            method.visitLdcInsn(org.objectweb.asm.Type.getObjectType(RUNNABLE));
            method.visitMethodInsn(
                Opcodes.INVOKESTATIC,
                "java/util/ServiceLoader",
                "load",
                "(Ljava/lang/Class;)Ljava/util/ServiceLoader;",
                false);
            method.visitMethodInsn(
                Opcodes.INVOKEVIRTUAL,
                "java/util/ServiceLoader",
                "iterator",
                "()Ljava/util/Iterator;",
                false);
            method.visitMethodInsn(
                Opcodes.INVOKEINTERFACE,
                "java/util/Iterator",
                "next",
                "()Ljava/lang/Object;",
                true);
            method.visitInsn(Opcodes.POP);
          }
          method.visitMethodInsn(
              Opcodes.INVOKESTATIC, needed, "run", NO_ARGS_VOID_DESCRIPTOR, false);
        });
    final String adapterBase = "fixture/AdapterBase";
    final Path adapterPath =
        ExplicitRuntimeMojoTestSupport.writeJar(
            work.resolve("adapter.jar"),
            Map.of(
                ADAPTER,
                classWithRun(
                    ADAPTER,
                    adapterBase,
                    service,
                    method -> {
                      method.visitLdcInsn(org.objectweb.asm.Type.getObjectType("missing/Optional"));
                      method.visitInsn(Opcodes.POP);
                    }),
                adapterBase,
                classWithRun(adapterBase, SQL_SUPERCLASS.replace('.', '/'), false, method -> {})),
            false,
            service
                ? Map.of(
                    "META-INF/services/java.lang.Runnable",
                    "fixture.Adapter\n".getBytes(java.nio.charset.StandardCharsets.UTF_8))
                : Map.of());
    final Path siblingPath =
        ExplicitRuntimeMojoTestSupport.writeJar(
            work.resolve("sibling.jar"),
            Map.of(
                needed,
                classWithRun(needed, service ? OBJECT : ADAPTER, false, method -> {}),
                UNUSED,
                classWithRun(UNUSED, OBJECT, false, method -> {})),
            false);
    final Artifact adapter = MavenBanAuditTestSupport.mavenArtifact("adapter", adapterPath);
    final Artifact sibling = MavenBanAuditTestSupport.mavenArtifact("sibling", siblingPath);
    project.setArtifacts(new LinkedHashSet<>(List.of(adapter, sibling)));
    final ElideMojo elide = ExplicitRuntimeMojoTestSupport.newElideMojo();
    final Path report = work.resolve(OBSERVED_JSON);
    set(elide, SUMMARY_FILE, report.toFile());
    ExplicitRuntimeMojoTestSupport.configure(elide, project, work, List.of(HOST));
    set(elide, "trimSkipArtifacts", List.of("fixture:adapter:1.0:jar:"));
    set(elide, "conservativeServiceLoaderRoots", false);
    Files.writeString(work.resolve("trace.txt"), "fixture.Main\nfixture.Sibling\n");
    final DefaultPlexusContainer container = new DefaultPlexusContainer();
    try {
      set(
          elide,
          "session",
          new MavenSession(
              container,
              new org.eclipse.aether.DefaultRepositorySystemSession(),
              new DefaultMavenExecutionRequest(),
              new DefaultMavenExecutionResult()));
      elide.execute();
      final Path previousReport = Files.copy(report, work.resolve("previous-report.json"));
      final Path publishedSibling = sibling.getFile().toPath();
      final Path previousSibling =
          Files.copy(publishedSibling, work.resolve("previous-sibling.jar"));
      sibling.setFile(siblingPath.toFile());
      set(elide, "runtimeInputs", List.of(HOST, reduced().toString()));
      assertAll(
          () -> assertThat(publishedSibling).isNotEqualTo(siblingPath),
          () ->
              assertThatThrownBy(elide::execute)
                  .isInstanceOf(MojoFailureException.class)
                  .hasMessageContaining(SQL_SUPERCLASS)
                  .hasMessageContaining("fixture.AdapterBase")
                  .hasMessageContaining(reduced().toString()),
          () ->
              assertThat(Files.mismatch(report, previousReport))
                  .as("prior successful report")
                  .isEqualTo(-1),
          () ->
              assertThat(Files.mismatch(publishedSibling, previousSibling))
                  .as("prior trimmed sibling")
                  .isEqualTo(-1),
          () -> assertThat(sibling.getFile()).isEqualTo(siblingPath.toFile()));
    } finally {
      container.dispose();
    }
  }

  @Test
  @SuppressWarnings("PMD.LawOfDemeter") // Maven exposes the published artifact path through File.
  void optionalSpringMetadataKeepsItsJarWithoutRequiringItsHierarchy() throws Exception {
    final MavenProject project = ExplicitRuntimeMojoTestSupport.project(work);
    writeApplication(
        project,
        method ->
            method.visitMethodInsn(
                Opcodes.INVOKESTATIC, SIBLING, "run", NO_ARGS_VOID_DESCRIPTOR, false));
    final Path optionalPath =
        ExplicitRuntimeMojoTestSupport.writeJar(
            work.resolve("optional.jar"),
            Map.of(
                "fixture/OptionalAdapter",
                classWithRun(
                    "fixture/OptionalAdapter", "missing/OptionalLogger", false, method -> {})),
            false,
            Map.of(
                "META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports",
                "fixture.OptionalAdapter\n".getBytes(java.nio.charset.StandardCharsets.UTF_8)));
    final Path siblingPath =
        ExplicitRuntimeMojoTestSupport.writeJar(
            work.resolve("sibling.jar"),
            Map.of(
                SIBLING,
                classWithRun(SIBLING, OBJECT, false, method -> {}),
                UNUSED,
                classWithRun(UNUSED, OBJECT, false, method -> {})),
            false);
    final Artifact optional = MavenBanAuditTestSupport.mavenArtifact("optional", optionalPath);
    final Artifact sibling = MavenBanAuditTestSupport.mavenArtifact("sibling", siblingPath);
    project.setArtifacts(new LinkedHashSet<>(List.of(optional, sibling)));
    final ElideMojo elide = ExplicitRuntimeMojoTestSupport.newElideMojo();
    final Path report = work.resolve(OBSERVED_JSON);
    set(elide, SUMMARY_FILE, report.toFile());
    ExplicitRuntimeMojoTestSupport.configure(elide, project, work, List.of(reduced().toString()));
    set(elide, "trimSkipArtifacts", List.of("fixture:optional:1.0:jar:"));
    Files.writeString(work.resolve("trace.txt"), "fixture.Main\nfixture.Sibling\n");
    final DefaultPlexusContainer container = new DefaultPlexusContainer();
    try {
      set(
          elide,
          "session",
          new MavenSession(
              container,
              new org.eclipse.aether.DefaultRepositorySystemSession(),
              new DefaultMavenExecutionRequest(),
              new DefaultMavenExecutionResult()));
      elide.execute();
      assertAll(
          () -> assertThat(Files.exists(report)).isTrue(),
          () -> assertThat(optional.getFile()).isEqualTo(optionalPath.toFile()),
          () -> assertThat(sibling.getFile().toPath()).isNotEqualTo(siblingPath),
          () ->
              assertThat(
                      MavenElisionReportWriter.read(report)
                          .executionEnvironment()
                          .runtimeCoverage()
                          .analyzedReleases())
                  .containsExactly(Runtime.version().feature()));
    } finally {
      container.dispose();
    }
  }

  @Test
  void missingModuleInAnUnchangedProjectLeavesAnUnavailableAdvisoryAndSuccessfulReport()
      throws Exception {
    final MavenProject project = ExplicitRuntimeMojoTestSupport.project(work);
    project.getProperties().setProperty("maven.compiler.release", "17");
    writeApplication(project, method -> {});
    final ClassWriter descriptor = new ClassWriter(0);
    descriptor.visit(Opcodes.V9, Opcodes.ACC_MODULE, "module-info", null, null, null);
    final ModuleVisitor module = descriptor.visitModule("fixture.application", 0, null);
    module.visitRequire("java.base", Opcodes.ACC_MANDATED, null);
    module.visitRequire(MISSING_MODULE, 0, null);
    module.visitEnd();
    descriptor.visitEnd();
    Files.write(
        ExplicitRuntimeMojoTestSupport.output(project).resolve(MODULE_INFO),
        descriptor.toByteArray());
    final ElideMojo mojo = ExplicitRuntimeMojoTestSupport.newElideMojo();
    final Path summary = work.resolve(OBSERVED_JSON);
    set(mojo, SUMMARY_FILE, summary.toFile());
    ExplicitRuntimeMojoTestSupport.configure(mojo, project, work, List.of(HOST));
    set(mojo, "trimJars", false);
    mojo.execute();
    final MavenElisionReportSnapshot saved = MavenElisionReportWriter.read(summary);
    final MavenRuntimeCoverage coverage = saved.executionEnvironment().runtimeCoverage();
    assertAll(
        () -> assertThat(coverage.inputs().getFirst().linkageProblem()).contains(MISSING_MODULE),
        () -> assertThat(coverage.analyzedReleases()).isEmpty(),
        () ->
            assertThat(MavenElisionReportWriter.render(saved))
                .anySatisfy(
                    line ->
                        assertThat(line)
                            .contains(
                                "Compiler target Java 17",
                                "[" + Runtime.version().feature() + "]",
                                "no runtime releases analyzed")),
        () ->
            assertThat(
                    Files.readString(
                        work.resolve("target")
                            .resolve(AdvisoryJdkModulesAnalyzer.ADVISORY_MODULES_FILENAME)))
                .contains("unavailable"));
  }

  @Test
  void obtainsAdviceFromCompatibleAlternateInstallation() throws Exception {
    org.junit.jupiter.api.Assumptions.assumeTrue(ToolProvider.findFirst("jdeps").isPresent());
    final MavenProject project = ExplicitRuntimeMojoTestSupport.project(work);
    writeApplication(project, method -> {});
    final Path installation = Files.createDirectory(work.resolve("alternate-runtime"));
    Files.createDirectory(installation.resolve("lib"));
    Files.copy(reduced().resolve(RELEASE), installation.resolve(RELEASE));
    Files.copy(reduced().resolve(MODULE_IMAGE), installation.resolve(MODULE_IMAGE));
    final ElideMojo mojo = ExplicitRuntimeMojoTestSupport.newElideMojo();
    ExplicitRuntimeMojoTestSupport.configure(mojo, project, work, List.of(installation.toString()));
    mojo.execute();
    assertThat(
            Files.readString(
                work.resolve("target")
                    .resolve(AdvisoryJdkModulesAnalyzer.ADVISORY_MODULES_FILENAME)))
        .isEqualTo("java.base\n");
  }

  private static Path reduced() {
    return shared.resolve("base-only");
  }

  private static void writeApplication(
      final MavenProject project, final Consumer<MethodVisitor> body) throws IOException {
    Files.write(
        Files.createDirectories(ExplicitRuntimeMojoTestSupport.output(project).resolve("fixture"))
            .resolve("Main.class"),
        classWithRun("fixture/Main", OBJECT, false, body));
  }

  private static byte[] classWithRun(
      final String name,
      final String superName,
      final boolean service,
      final Consumer<MethodVisitor> body) {
    final ClassWriter writer = new ClassWriter(0);
    writer.visit(
        Opcodes.V11,
        Opcodes.ACC_PUBLIC,
        name,
        null,
        superName,
        service ? new String[] {RUNNABLE} : null);
    final MethodVisitor constructor =
        writer.visitMethod(Opcodes.ACC_PUBLIC, "<init>", NO_ARGS_VOID_DESCRIPTOR, null, null);
    constructor.visitCode();
    constructor.visitVarInsn(Opcodes.ALOAD, 0);
    constructor.visitMethodInsn(
        Opcodes.INVOKESPECIAL, superName, "<init>", NO_ARGS_VOID_DESCRIPTOR, false);
    constructor.visitInsn(Opcodes.RETURN);
    constructor.visitMaxs(1, 1);
    constructor.visitEnd();
    final MethodVisitor method =
        writer.visitMethod(
            service ? Opcodes.ACC_PUBLIC : Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
            "run",
            NO_ARGS_VOID_DESCRIPTOR,
            null,
            null);
    method.visitCode();
    body.accept(method);
    method.visitInsn(Opcodes.RETURN);
    method.visitMaxs(1, service ? 1 : 0);
    method.visitEnd();
    writer.visitEnd();
    return writer.toByteArray();
  }
}
