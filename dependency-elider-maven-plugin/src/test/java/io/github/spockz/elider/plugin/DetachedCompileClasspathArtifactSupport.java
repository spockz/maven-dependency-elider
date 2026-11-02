/* WHY: Shares archive and Maven artifact construction across detached classpath tests. */

package io.github.spockz.elider.plugin;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import org.apache.maven.RepositoryUtils;
import org.apache.maven.artifact.Artifact;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;

/** Builds classpath artifacts for direct and Resolver-backed analysis scenarios. */
final class DetachedCompileClasspathArtifactSupport {
  private DetachedCompileClasspathArtifactSupport() {
    // Static fixture creation keeps the support type from becoming a test instance.
  }

  /* package */ static Path libraryJar(final Path temporaryDirectory) throws IOException {
    final Path jar = temporaryDirectory.resolve("compile-api.jar");
    final ClassWriter writer = new ClassWriter(0);
    writer.visit(
        Opcodes.V17, Opcodes.ACC_PUBLIC, "org/example/api/Api", null, "java/lang/Object", null);
    writer.visitEnd();
    try (ZipOutputStream zip = new ZipOutputStream(Files.newOutputStream(jar))) {
      zip.putNextEntry(new ZipEntry("org/example/api/Api.class"));
      zip.write(writer.toByteArray());
      zip.closeEntry();
    }
    return jar;
  }

  /* package */ static Artifact toMavenArtifact(
      final String groupId,
      final String artifactId,
      final String version,
      final String scope,
      final String type,
      final String extension,
      final boolean addedToClasspath,
      final Path file) {
    final org.eclipse.aether.artifact.Artifact resolverArtifact =
        new org.eclipse.aether.artifact.DefaultArtifact(
            groupId,
            artifactId,
            "",
            extension,
            version,
            Map.of("type", type, "constitutesBuildPath", Boolean.toString(addedToClasspath)),
            file.toFile());
    final Artifact mavenArtifact = RepositoryUtils.toArtifact(resolverArtifact);
    mavenArtifact.setScope(scope);
    return mavenArtifact;
  }
}
