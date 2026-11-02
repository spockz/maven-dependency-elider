/* WHY: Builds archive and project fixtures shared by AnalyzeMojo tests. */

package io.github.spockz.elider.plugin;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.artifact.DefaultArtifact;
import org.apache.maven.artifact.handler.DefaultArtifactHandler;
import org.apache.maven.project.MavenProject;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;

/** Creates temporary artifact files used by focused AnalyzeMojo tests. */
final class AnalyzeMojoTestArtifactSupport {
  private AnalyzeMojoTestArtifactSupport() {
    // WHY: Static helpers need no test instance.
  }

  /* package */ static Artifact artifact(
      final Path temporaryDirectory,
      final String artifactId,
      final String version,
      final String scope,
      final String type,
      final String fileName,
      final String classEntry)
      throws IOException {
    final Path file = temporaryDirectory.resolve(fileName);
    try (ZipOutputStream output = new ZipOutputStream(Files.newOutputStream(file))) {
      writeClassEntry(output, classEntry.substring(0, classEntry.length() - ".class".length()));
    }
    final Artifact artifact =
        new DefaultArtifact(
            "org.example",
            artifactId,
            version,
            scope,
            type,
            null,
            new DefaultArtifactHandler(type));
    artifact.setFile(file.toFile());
    return artifact;
  }

  /* package */ static Artifact artifactWithClasses(
      final Path temporaryDirectory, final String artifactId, final String fileName)
      throws IOException {
    final Path file = temporaryDirectory.resolve(fileName);
    try (ZipOutputStream output = new ZipOutputStream(Files.newOutputStream(file))) {
      writeClassEntry(output, "sample/Keep");
      writeClassEntry(output, "sample/Drop");
    }
    final Artifact artifact =
        new DefaultArtifact(
            "org.example",
            artifactId,
            "1.0",
            "runtime",
            "jar",
            null,
            new DefaultArtifactHandler("jar"));
    artifact.setFile(file.toFile());
    return artifact;
  }

  /* package */ static Fixture fixture(final Path temporaryDirectory, final String traceContent)
      throws IOException, ReflectiveOperationException {
    final Artifact used =
        artifact(
            temporaryDirectory,
            "used",
            "1.0",
            "compile",
            "jar",
            "fixture.jar",
            "used/Sample.class");
    final MavenProject project = new MavenProject();
    project.setArtifacts(new LinkedHashSet<>(Set.of(used)));
    final Path trace = temporaryDirectory.resolve("fixture.lst");
    Files.writeString(trace, traceContent);
    final AnalyzeMojo mojo = new AnalyzeMojo();
    AnalyzeMojoTestFieldSupport.set(mojo, "project", project);
    AnalyzeMojoTestFieldSupport.set(mojo, "traceFiles", List.of(trace.toFile()));
    AnalyzeMojoTestFieldSupport.set(
        mojo, "reportFile", temporaryDirectory.resolve("fixture-report.json").toFile());
    return new Fixture(mojo, project);
  }

  private static void writeClassEntry(final ZipOutputStream output, final String className)
      throws IOException {
    output.putNextEntry(new ZipEntry(className + ".class"));
    final ClassWriter writer = new ClassWriter(0);
    writer.visit(Opcodes.V21, Opcodes.ACC_PUBLIC, className, null, "java/lang/Object", null);
    writer.visitEnd();
    output.write(writer.toByteArray());
    output.closeEntry();
  }

  /** Carries the Mojo and project produced for a single analysis scenario. */
  /* package */ record Fixture(AnalyzeMojo mojo, MavenProject project) {}
}
