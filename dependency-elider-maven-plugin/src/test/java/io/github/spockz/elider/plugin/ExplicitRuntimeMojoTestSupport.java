/* WHY: Goal fixtures opt in to the runtime they use for class linkage. */

package io.github.spockz.elider.plugin;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.jar.Attributes;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;
import org.apache.maven.model.Build;
import org.apache.maven.project.MavenProject;

@SuppressWarnings({"PMD.CommentRequired", "PMD.LawOfDemeter"})
final class ExplicitRuntimeMojoTestSupport {
  private ExplicitRuntimeMojoTestSupport() {}

  /* package */ static ElideMojo newElideMojo() {
    final ElideMojo mojo = new ElideMojo();
    mojo.runtimeInputs = List.of(System.getProperty("java.home"));
    return mojo;
  }

  /* package */ static AnalyzeMojo newAnalyzeMojo() {
    final AnalyzeMojo mojo = new AnalyzeMojo();
    mojo.runtimeInputs = List.of(System.getProperty("java.home"));
    return mojo;
  }

  /* package */ static MavenProject project(final Path work) throws IOException {
    final MavenProject project = MavenBanAuditTestSupport.project(work);
    final Build build = new Build();
    build.setDirectory(work.resolve("target").toString());
    build.setOutputDirectory(Files.createDirectories(work.resolve("target/classes")).toString());
    project.setBuild(build);
    return project;
  }

  /* package */ static void configure(
      final AbstractElisionMojo mojo,
      final MavenProject project,
      final Path work,
      final List<String> inputs)
      throws IOException, ReflectiveOperationException {
    final Path trace = Files.writeString(work.resolve("trace.txt"), "fixture.Main\n");
    AnalyzeMojoTestFieldSupport.set(mojo, "project", project);
    AnalyzeMojoTestFieldSupport.set(mojo, "traceFiles", List.of(trace.toFile()));
    AnalyzeMojoTestFieldSupport.set(
        mojo, "reportFile", work.resolve(mojo.getClass().getSimpleName() + ".json").toFile());
    AnalyzeMojoTestFieldSupport.set(mojo, "cveCacheDirectory", work.resolve("advisories").toFile());
    AnalyzeMojoTestFieldSupport.set(mojo, "productionClassesComplete", true);
    AnalyzeMojoTestFieldSupport.set(mojo, "trimJars", true);
    AnalyzeMojoTestFieldSupport.set(mojo, "runtimeInputs", inputs);
  }

  /* package */ static Path output(final MavenProject project) {
    return Path.of(project.getBuild().getOutputDirectory());
  }

  /* package */ static Path writeJar(
      final Path path, final Map<String, byte[]> entries, final boolean multiRelease)
      throws IOException {
    return writeJar(path, entries, multiRelease, Map.of());
  }

  /* package */ static Path writeJar(
      final Path path,
      final Map<String, byte[]> classes,
      final boolean multiRelease,
      final Map<String, byte[]> resources)
      throws IOException {
    final Manifest manifest = new Manifest();
    manifest.getMainAttributes().put(Attributes.Name.MANIFEST_VERSION, "1.0");
    if (multiRelease) {
      manifest.getMainAttributes().put(Attributes.Name.MULTI_RELEASE, "true");
    }
    try (JarOutputStream jar = new JarOutputStream(Files.newOutputStream(path), manifest)) {
      writeEntries(jar, classes, ".class");
      writeEntries(jar, resources, "");
    }
    return path;
  }

  @SuppressWarnings("PMD.AvoidInstantiatingObjectsInLoops")
  private static void writeEntries(
      final JarOutputStream jar, final Map<String, byte[]> entries, final String suffix)
      throws IOException {
    for (final Map.Entry<String, byte[]> entry : entries.entrySet()) {
      jar.putNextEntry(new JarEntry(entry.getKey() + suffix));
      jar.write(entry.getValue());
      jar.closeEntry();
    }
  }
}
