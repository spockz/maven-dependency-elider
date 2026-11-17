/* WHY: Enumerates shipped-runtime output and resource providers for prerequisite proof. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.applicability.PreconditionClassInventory.Provider;
import io.github.spockz.elider.applicability.PreconditionClassInventory.ProviderKind;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.model.Resource;
import org.apache.maven.project.MavenProject;

/** Scans production output and resources for runtime class and resource providers. */
@SuppressWarnings({
  "PMD.CommentDefaultAccessModifier",
  "PMD.CommentRequired",
  "PMD.CyclomaticComplexity",
  "PMD.LawOfDemeter",
  "PMD.UseConcurrentHashMap"
})
final class MavenPreconditionProviderRoots {
  private static final String CLASS_SUFFIX = ".class";

  private MavenPreconditionProviderRoots() {}

  record Capture(List<Provider> providers, String incompleteDetail) {
    Capture {
      providers = List.copyOf(providers);
    }
  }

  static Capture capture(
      final MavenProject project,
      final MavenSession session,
      final ElisionAnalysisModel.AnalysisEvidence evidence,
      final boolean explicitCompleteness)
      throws IOException {
    if (project == null || project.getBuild() == null) {
      throw new IOException("Maven project build roots are unavailable");
    }
    MavenPreconditionGenerationGuard.requireKnownProviderGeneration(
        project,
        session,
        evidence.trustedProcessClassesContext(),
        evidence.productionClassesComplete());
    final List<Root> roots = declaredRoots(project, evidence);
    requireTestOutputSeparated(project, roots);
    final Map<Path, Provider> providers = new LinkedHashMap<>();
    for (final Root root : roots) {
      addProviders(root, providers);
    }
    final String incompleteDetail =
        explicitCompleteness
                || evidence.productionClassesComplete()
                || evidence.trustedProcessClassesContext()
            ? null
            : "Production output is not known complete before the process-classes phase";
    return new Capture(List.copyOf(providers.values()), incompleteDetail);
  }

  private static List<Root> declaredRoots(
      final MavenProject project, final ElisionAnalysisModel.AnalysisEvidence evidence)
      throws IOException {
    final List<Root> roots = new ArrayList<>();
    addDirectoryRoot(roots, project, "production-output", project.getBuild().getOutputDirectory());
    addResources(roots, project, "production-resource", project.getBuild().getResources());
    if (evidence.bytecodeScan().isPresent()) {
      final Path scannedOutput = evidence.bytecodeScan().orElseThrow().scope();
      if (roots.stream()
          .noneMatch(root -> root.path().equals(scannedOutput.toAbsolutePath().normalize()))) {
        roots.add(
            new Root("configured-production-output", scannedOutput.toAbsolutePath().normalize()));
      }
    }
    return List.copyOf(roots);
  }

  private static void requireTestOutputSeparated(
      final MavenProject project, final List<Root> runtimeRoots) throws IOException {
    final String configuredTestOutput = project.getBuild().getTestOutputDirectory();
    if (configuredTestOutput == null || configuredTestOutput.isBlank()) {
      throw new IOException("Maven test output directory is unavailable");
    }
    final Path testOutput = resolveProjectPath(project, configuredTestOutput);
    for (final Root runtimeRoot : runtimeRoots) {
      if (testOutput.startsWith(runtimeRoot.path()) || runtimeRoot.path().startsWith(testOutput)) {
        throw new IOException(
            "Maven test output overlaps production provider root: " + runtimeRoot.path());
      }
    }
  }

  private static void addResources(
      final List<Root> roots,
      final MavenProject project,
      final String kind,
      final Collection<Resource> resources)
      throws IOException {
    if (resources == null) {
      throw new IOException("Maven " + kind + " roots are unavailable");
    }
    for (final Resource resource : resources) {
      if (resource.getDirectory() == null || resource.getDirectory().isBlank()) {
        throw new IOException("Maven " + kind + " root is blank");
      }
      roots.add(new Root(kind, resolveProjectPath(project, resource.getDirectory())));
    }
  }

  private static void addDirectoryRoot(
      final List<Root> roots,
      final MavenProject project,
      final String kind,
      final String configuredRoot)
      throws IOException {
    if (configuredRoot == null || configuredRoot.isBlank()) {
      throw new IOException("Maven " + kind + " root is unavailable");
    }
    roots.add(new Root(kind, resolveProjectPath(project, configuredRoot)));
  }

  private static Path resolveProjectPath(final MavenProject project, final String configuredPath) {
    final Path path = Path.of(configuredPath);
    if (path.isAbsolute() || project.getBasedir() == null) {
      return path.toAbsolutePath().normalize();
    }
    return project.getBasedir().toPath().resolve(path).toAbsolutePath().normalize();
  }

  private static void addProviders(final Root root, final Map<Path, Provider> providers)
      throws IOException {
    if (Files.notExists(root.path())) {
      return;
    }
    if (!Files.isDirectory(root.path())) {
      throw new IOException("Maven provider root is not a directory: " + root.path());
    }
    try (Stream<Path> paths = Files.walk(root.path())) {
      for (final Path path : paths.sorted().toList()) {
        if (Files.isDirectory(path)) {
          continue;
        }
        if (!Files.isRegularFile(path)) {
          throw new IOException("Unsupported filesystem entry in Maven provider root: " + path);
        }
        final Path normalized = path.toAbsolutePath().normalize();
        if (providers.containsKey(normalized)) {
          continue;
        }
        final ProviderKind kind =
            normalized.toString().endsWith(CLASS_SUFFIX)
                ? ProviderKind.APPLICATION_CLASS_FILE
                : ProviderKind.APPLICATION_RESOURCE_FILE;
        providers.putIfAbsent(
            normalized,
            kind == ProviderKind.APPLICATION_CLASS_FILE
                ? Provider.applicationClassFile(normalized)
                : Provider.applicationResourceFile(normalized));
      }
    }
  }

  private record Root(String kind, Path path) {}
}
