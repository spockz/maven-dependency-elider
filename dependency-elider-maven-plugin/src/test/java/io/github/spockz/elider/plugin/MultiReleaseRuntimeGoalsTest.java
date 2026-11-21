/* WHY: Exercises physical cross-release trimming with two distinct supplied runtime images. */

package io.github.spockz.elider.plugin;

import static io.github.spockz.elider.plugin.AnalyzeMojoTestFieldSupport.set;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import org.apache.maven.execution.DefaultMavenExecutionRequest;
import org.apache.maven.execution.DefaultMavenExecutionResult;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.project.MavenProject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

@SuppressWarnings({"PMD.AtLeastOneConstructor", "PMD.CommentRequired"})
final class MultiReleaseRuntimeGoalsTest {
  private static final String HOST = System.getProperty("java.home");
  private static final String ENTRY = "fixture/Entry";
  private static final String LOWER = "sibling/Lower";
  private static final String UPPER = "sibling/Upper";
  private static final String UNUSED = "sibling/Unused";
  private static final String CLASS_SUFFIX = ".class";
  @TempDir private Path work;

  @Test
  void retainsDisjointSiblingClosureForTwoActualRuntimeReleases() throws Exception {
    final String second = System.getProperty("elide.test.additionalRuntime");
    assumeTrue(second != null, "Supply a second image with -Delide.test.additionalRuntime");
    final int host = Runtime.version().feature();
    final int other =
        io.github.spockz.elider.trimmer.JdkPlatformContext.inspectRuntime(Path.of(second))
            .runtimeRelease();
    assumeTrue(other >= 11 && other != host, "The fixture needs two distinct modular releases");
    final MavenProject project = ExplicitRuntimeMojoTestSupport.project(work);
    final int high = Math.max(host, other);
    project
        .getProperties()
        .setProperty("maven.compiler.release", Integer.toString(Math.min(host, other)));
    final String upperPath = "META-INF/versions/" + high + "/" + ENTRY;
    final Path program =
        ExplicitRuntimeMojoTestSupport.writeJar(
            work.resolve("program.jar"),
            Map.of(ENTRY, classCalling(ENTRY, LOWER), upperPath, classCalling(ENTRY, UPPER)),
            true);
    final Path sibling =
        ExplicitRuntimeMojoTestSupport.writeJar(
            work.resolve("sibling.jar"),
            Map.of(
                LOWER,
                classCalling(LOWER, null),
                UPPER,
                classCalling(UPPER, null),
                UNUSED,
                classCalling(UNUSED, null)),
            false);
    final org.apache.maven.artifact.Artifact programArtifact =
        MavenBanAuditTestSupport.mavenArtifact("entry", program);
    final org.apache.maven.artifact.Artifact siblingArtifact =
        MavenBanAuditTestSupport.mavenArtifact("sibling", sibling);
    project.setArtifacts(new LinkedHashSet<>(List.of(programArtifact, siblingArtifact)));
    Files.write(
        Files.createDirectories(ExplicitRuntimeMojoTestSupport.output(project).resolve("fixture"))
            .resolve("Main.class"),
        classCalling("fixture/Main", ENTRY));
    final ElideMojo elide = ExplicitRuntimeMojoTestSupport.newElideMojo();
    final Path report = work.resolve("observed.json");
    set(elide, "summaryFile", report.toFile());
    ExplicitRuntimeMojoTestSupport.configure(elide, project, work, List.of(HOST, second));
    Files.writeString(work.resolve("trace.txt"), "fixture.Main\nfixture.Entry\n");
    final org.codehaus.plexus.DefaultPlexusContainer container =
        new org.codehaus.plexus.DefaultPlexusContainer();
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
    } finally {
      container.dispose();
    }
    final MavenElisionReportSnapshot observed = MavenElisionReportWriter.read(report);
    assertAll(
        () ->
            assertThat(observed.executionEnvironment().runtimeCoverage().analyzedReleases())
                .containsExactly(Math.min(host, other), high),
        () -> {
          try (JarFile trimmed = new JarFile(siblingArtifact.getFile())) {
            assertThat(trimmed.stream().map(JarEntry::getName))
                .contains(LOWER + CLASS_SUFFIX, UPPER + CLASS_SUFFIX)
                .doesNotContain(UNUSED + CLASS_SUFFIX);
          }
        },
        () -> {
          try (JarFile trimmed = new JarFile(programArtifact.getFile())) {
            assertThat(trimmed.getJarEntry(upperPath + CLASS_SUFFIX)).isNotNull();
          }
        });
  }

  private static byte[] classCalling(final String name, final String referencedOwner) {
    final ClassWriter writer = new ClassWriter(0);
    writer.visit(Opcodes.V11, Opcodes.ACC_PUBLIC, name, null, "java/lang/Object", null);
    final MethodVisitor method =
        writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "run", "()V", null, null);
    method.visitCode();
    if (referencedOwner != null) {
      method.visitMethodInsn(Opcodes.INVOKESTATIC, referencedOwner, "run", "()V", false);
    }
    method.visitInsn(Opcodes.RETURN);
    method.visitMaxs(0, 0);
    method.visitEnd();
    writer.visitEnd();
    return writer.toByteArray();
  }
}
