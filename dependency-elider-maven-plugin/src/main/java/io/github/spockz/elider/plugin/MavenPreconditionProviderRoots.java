/* WHY: Re-enumerates Maven application roots and binds providers to their file bytes. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.PreconditionClassInventory.Provider;
import io.github.spockz.elider.model.PreconditionClassInventory.ProviderKind;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.model.Resource;
import org.apache.maven.project.MavenProject;

/** Scans Maven source, output, and resource roots for class providers. */
@SuppressWarnings({
  "PMD.CommentDefaultAccessModifier",
  "PMD.CouplingBetweenObjects",
  "PMD.CyclomaticComplexity",
  "PMD.GodClass",
  "PMD.LawOfDemeter",
  "PMD.TooManyMethods",
  "PMD.UseConcurrentHashMap"
})
final class MavenPreconditionProviderRoots {
  /** Source languages not parsed by the Java declaration scanner. */
  private static final List<String> UNSUPPORTED_SOURCE_SUFFIXES =
      List.of(".scala", ".kt", ".kts", ".groovy");

  /** Java source suffix accepted by the independent source declaration scanner. */
  private static final String JAVA_SUFFIX = ".java";

  /** Class file suffix used to select the bytecode provider reader. */
  private static final String CLASS_SUFFIX = ".class";

  /** Prefix used to identify errors in declared Maven inputs. */
  private static final String MAVEN_PREFIX = "Maven ";

  private MavenPreconditionProviderRoots() {}

  record Capture(List<Provider> providers, String fingerprint) {
    Capture {
      providers = List.copyOf(providers);
    }
  }

  static Capture capture(
      final MavenProject project,
      final MavenSession session,
      final MavenElisionService.Analysis analysis,
      final Collection<Path> stages)
      throws IOException {
    if (project == null || project.getBuild() == null) {
      throw new IOException(MAVEN_PREFIX + "project build roots are unavailable");
    }
    MavenPreconditionGenerationGuard.requireKnownProviderGeneration(
        project, session, analysis.trustedProcessClassesContext());
    if (!analysis.trustedProcessClassesContext()
        && MavenElisionService.hasUnknownSourceGeneration(project, session)) {
      throw new IOException(MAVEN_PREFIX + "build has an unsupported or unknown source generator");
    }
    final List<Path> normalizedStages =
        stages.stream().map(path -> path.toAbsolutePath().normalize()).sorted().toList();
    final List<RootFiles> rootsBeforeScan = declaredRoots(project, analysis, normalizedStages);
    final Map<Path, String> sourceDigests = sourceDigests(rootsBeforeScan);
    final List<String> membersBeforeScan = rootMembers(rootsBeforeScan);
    final List<Provider> providers = applicationProviders(rootsBeforeScan);
    rejectUnsupportedSourceFiles(rootsBeforeScan);
    verifyCapturedRootDigests(rootsBeforeScan, providers, sourceDigests);
    final List<RootFiles> rootsAfterScan = declaredRoots(project, analysis, normalizedStages);
    final List<String> membersAfterScan = rootMembers(rootsAfterScan);
    if (!rootIdentity(rootsBeforeScan).equals(rootIdentity(rootsAfterScan))
        || !membersBeforeScan.equals(membersAfterScan)) {
      throw new IOException("Maven provider roots changed during inventory capture");
    }
    verifyCapturedRootDigests(rootsAfterScan, providers, sourceDigests);
    return new Capture(
        providers,
        fingerprint(
            rootIdentity(rootsAfterScan), membersAfterScan, stageIdentity(normalizedStages)));
  }

  private static List<RootFiles> declaredRoots(
      final MavenProject project,
      final MavenElisionService.Analysis analysis,
      final List<Path> stages)
      throws IOException {
    final List<RootFiles> roots = new ArrayList<>();
    addSourceRoots(roots, "production-source", project, project.getCompileSourceRoots());
    addSourceRoots(roots, "test-source", project, project.getTestCompileSourceRoots());
    final Path buildDirectory = resolvedBuildDirectory(project);
    addSourceRoots(
        roots,
        "generated-production-source",
        project,
        List.of(buildDirectory.resolve("generated-sources/annotations").toString()));
    addSourceRoots(
        roots,
        "generated-test-source",
        project,
        List.of(buildDirectory.resolve("generated-test-sources/test-annotations").toString()));
    addDirectoryRoot(
        roots, "production-output", project, project.getBuild().getOutputDirectory(), stages);
    addDirectoryRoot(
        roots, "test-output", project, project.getBuild().getTestOutputDirectory(), stages);
    addResources(roots, "production-resource", project, project.getBuild().getResources(), stages);
    addResources(roots, "test-resource", project, project.getBuild().getTestResources(), stages);
    if (analysis.bytecodeScan().isPresent()) {
      final Path scannedOutput = analysis.bytecodeScan().orElseThrow().scope();
      if (!containsRoot(roots, scannedOutput)) {
        addDirectoryRoot(
            roots, "configured-production-output", project, scannedOutput.toString(), stages);
      }
    }
    return List.copyOf(roots);
  }

  private static Path resolvedBuildDirectory(final MavenProject project) throws IOException {
    final String configuredDirectory = project.getBuild().getDirectory();
    if (configuredDirectory == null
        || configuredDirectory.isBlank()
        || configuredDirectory.contains("${")
        || configuredDirectory.contains("}")) {
      throw new IOException("Maven build directory is unavailable or unresolved");
    }
    final Path directory = Path.of(configuredDirectory);
    if (!directory.isAbsolute() && project.getBasedir() == null) {
      throw new IOException("Maven build directory has no project base directory");
    }
    return resolveProjectPath(project, configuredDirectory).toAbsolutePath().normalize();
  }

  private static void addSourceRoots(
      final List<RootFiles> roots,
      final String kind,
      final MavenProject project,
      final Collection<String> configuredRoots)
      throws IOException {
    if (configuredRoots == null) {
      throw new IOException(MAVEN_PREFIX + kind + " roots are unavailable");
    }
    for (final String configuredRoot : configuredRoots) {
      if (configuredRoot == null || configuredRoot.isBlank()) {
        throw new IOException(MAVEN_PREFIX + kind + " root is blank");
      }
      roots.add(scanRoot(kind, resolveProjectPath(project, configuredRoot), List.of()));
    }
  }

  private static void addResources(
      final List<RootFiles> roots,
      final String kind,
      final MavenProject project,
      final Collection<Resource> resources,
      final List<Path> stages)
      throws IOException {
    if (resources == null) {
      throw new IOException(MAVEN_PREFIX + kind + " roots are unavailable");
    }
    for (final Resource resource : resources) {
      if (resource.getDirectory() == null || resource.getDirectory().isBlank()) {
        throw new IOException(MAVEN_PREFIX + kind + " root is blank");
      }
      roots.add(scanRoot(kind, resolveProjectPath(project, resource.getDirectory()), stages));
    }
  }

  private static void addDirectoryRoot(
      final List<RootFiles> roots,
      final String kind,
      final MavenProject project,
      final String configuredRoot,
      final List<Path> stages)
      throws IOException {
    if (configuredRoot == null || configuredRoot.isBlank()) {
      throw new IOException(MAVEN_PREFIX + kind + " root is unavailable");
    }
    roots.add(scanRoot(kind, resolveProjectPath(project, configuredRoot), stages));
  }

  private static Path resolveProjectPath(final MavenProject project, final String configuredPath) {
    final Path path = Path.of(configuredPath);
    if (path.isAbsolute() || project.getBasedir() == null) {
      return path;
    }
    return project.getBasedir().toPath().resolve(path);
  }

  private static RootFiles scanRoot(
      final String kind, final Path configuredRoot, final List<Path> stages) throws IOException {
    final Path root = configuredRoot.toAbsolutePath().normalize();
    if (Files.isSymbolicLink(root)) {
      throw new IOException("Declared Maven provider root is a symbolic link: " + root);
    }
    if (Files.notExists(root, LinkOption.NOFOLLOW_LINKS)) {
      return new RootFiles(kind, root.toString(), false, List.of());
    }
    if (!Files.exists(root, LinkOption.NOFOLLOW_LINKS)) {
      throw new IOException("Cannot determine declared Maven provider root state: " + root);
    }
    final Path canonicalRoot = root.toRealPath();
    if (!canonicalRoot.equals(root)) {
      throw new IOException("Declared Maven provider root is not canonical: " + root);
    }
    if (!Files.isDirectory(canonicalRoot)) {
      throw new IOException("Declared Maven provider root is not a directory: " + root);
    }
    final Set<Path> excludedStages = new LinkedHashSet<>(stages);
    final List<Path> members = regularMembers(canonicalRoot, excludedStages);
    return new RootFiles(kind, canonicalRoot.toString(), true, members);
  }

  private static List<Path> regularMembers(final Path root, final Set<Path> excludedStages)
      throws IOException {
    final List<Path> members = new ArrayList<>();
    try (Stream<Path> paths = Files.walk(root)) {
      for (final Path path : paths.sorted().toList()) {
        if (Files.isSymbolicLink(path)) {
          throw new IOException("Symbolic link in declared Maven provider root: " + path);
        }
        if (Files.isDirectory(path)) {
          continue;
        }
        if (!Files.isRegularFile(path)) {
          throw new IOException("Unsupported filesystem entry in Maven provider root: " + path);
        }
        if (!excludedStages.contains(path.toAbsolutePath().normalize())) {
          members.add(canonicalRegularFile(path));
        }
      }
    }
    return List.copyOf(members);
  }

  private static List<Provider> applicationProviders(final List<RootFiles> roots)
      throws IOException {
    final Map<Path, Provider> providersByPath = new LinkedHashMap<>();
    for (final RootFiles root : roots) {
      addRootProviders(root, providersByPath);
    }
    return List.copyOf(providersByPath.values());
  }

  private static void addRootProviders(
      final RootFiles root, final Map<Path, Provider> providersByPath) throws IOException {
    if (root.kind().endsWith("-source")) {
      addSourceProviders(root, providersByPath);
    } else {
      addFileProviders(root, providersByPath);
    }
  }

  private static void addSourceProviders(
      final RootFiles root, final Map<Path, Provider> providersByPath) throws IOException {
    final List<Path> javaSources =
        root.members().stream().filter(path -> path.toString().endsWith(JAVA_SUFFIX)).toList();
    final Map<Path, Set<String>> declarations = MavenSourceDeclarationScanner.scan(javaSources);
    for (final Path source : javaSources) {
      providersByPath.put(
          source,
          Provider.applicationSourceFile(source, declarations.getOrDefault(source, Set.of())));
    }
    addFileProviders(
        new RootFiles(
            root.kind(),
            root.configuredPath(),
            root.exists(),
            root.members().stream()
                .filter(path -> !path.toString().endsWith(JAVA_SUFFIX))
                .toList()),
        providersByPath);
  }

  private static void rejectUnsupportedSourceFiles(final List<RootFiles> roots) throws IOException {
    for (final RootFiles root : roots) {
      if (!root.kind().endsWith("-source")) {
        continue;
      }
      for (final Path member : root.members()) {
        final Path fileName = member.getFileName();
        if (fileName == null) {
          throw new IOException("Cannot determine declared source member name: " + member);
        }
        final String name = fileName.toString().toLowerCase(Locale.ROOT);
        if (UNSUPPORTED_SOURCE_SUFFIXES.stream().anyMatch(name::endsWith)) {
          throw new IOException("Unsupported non-Java source in declared root: " + member);
        }
      }
    }
  }

  private static void addFileProviders(
      final RootFiles root, final Map<Path, Provider> providersByPath) throws IOException {
    for (final Path member : root.members()) {
      final ProviderKind kind =
          member.toString().endsWith(CLASS_SUFFIX)
              ? ProviderKind.APPLICATION_CLASS_FILE
              : ProviderKind.APPLICATION_RESOURCE_FILE;
      final Provider provider =
          kind == ProviderKind.APPLICATION_CLASS_FILE
              ? Provider.applicationClassFile(member)
              : Provider.applicationResourceFile(member);
      providersByPath.putIfAbsent(member, provider);
    }
  }

  private static boolean containsRoot(final List<RootFiles> roots, final Path candidate) {
    final Path normalized = candidate.toAbsolutePath().normalize();
    return roots.stream().anyMatch(root -> normalized.toString().equals(root.configuredPath()));
  }

  @SuppressWarnings("PMD.CognitiveComplexity")
  private static Map<Path, String> sourceDigests(final List<RootFiles> roots) throws IOException {
    final Map<Path, String> digests = new HashMap<>();
    for (final RootFiles root : roots) {
      if (root.kind().endsWith("-source")) {
        for (final Path source : root.members()) {
          if (!source.toString().endsWith(JAVA_SUFFIX)) {
            continue;
          }
          final String current = ArtifactFileDigest.sha256(source);
          final String previous = digests.putIfAbsent(source, current);
          if (previous != null && !previous.equals(current)) {
            throw new IOException("Maven source changed before declaration scanning: " + source);
          }
        }
      }
    }
    return Map.copyOf(digests);
  }

  private static void verifyCapturedRootDigests(
      final List<RootFiles> roots,
      final List<Provider> providers,
      final Map<Path, String> sourceDigests)
      throws IOException {
    final Map<Path, String> digests = new HashMap<>();
    for (final Provider provider : providers) {
      digests.put(provider.path(), provider.sha256());
    }
    for (final RootFiles root : roots) {
      for (final Path member : root.members()) {
        final String capturedDigest = digests.get(member);
        if (capturedDigest == null) {
          throw new IOException("Maven provider was not inventoried: " + member);
        }
        final String sourceDigest = sourceDigests.get(member);
        if (sourceDigest != null && !sourceDigest.equals(capturedDigest)) {
          throw new IOException("Maven source changed during declaration scanning: " + member);
        }
        if (!capturedDigest.equals(ArtifactFileDigest.sha256(member))) {
          throw new IOException(
              MAVEN_PREFIX + "provider changed during inventory capture: " + member);
        }
      }
    }
  }

  private static Path canonicalRegularFile(final Path path) throws IOException {
    final Path absolute = path.toAbsolutePath().normalize();
    if (Files.isSymbolicLink(absolute)) {
      throw new IOException("Maven class provider is a symbolic link: " + absolute);
    }
    if (!Files.isRegularFile(absolute)) {
      throw new IOException("Maven class provider is not a regular file: " + absolute);
    }
    final Path canonical = absolute.toRealPath();
    if (!canonical.equals(absolute)) {
      throw new IOException("Maven class provider path is not canonical: " + absolute);
    }
    return canonical;
  }

  private static List<String> rootIdentity(final List<RootFiles> roots) {
    final List<String> identity = new ArrayList<>();
    for (final RootFiles root : roots) {
      identity.add(root.kind() + "\0" + root.configuredPath() + "\0" + root.exists());
    }
    return List.copyOf(identity);
  }

  private static List<String> rootMembers(final List<RootFiles> roots) throws IOException {
    final List<String> members = new ArrayList<>();
    for (final RootFiles root : roots) {
      for (final Path member : root.members()) {
        members.add(root.kind() + "\0" + member + "\0" + ArtifactFileDigest.sha256(member));
      }
    }
    return List.copyOf(members);
  }

  private static List<String> stageIdentity(final List<Path> stages) {
    return stages.stream().map(path -> "stage\0" + path).toList();
  }

  private static String fingerprint(
      final List<String> identity, final List<String> members, final List<String> stages)
      throws IOException {
    try {
      final ByteArrayOutputStream bytes = new ByteArrayOutputStream();
      try (DataOutputStream output = new DataOutputStream(bytes)) {
        writeValues(output, identity);
        output.writeInt(-1);
        writeValues(output, members);
        output.writeInt(-1);
        writeValues(output, stages);
      }
      return HexFormat.of()
          .formatHex(MessageDigest.getInstance("SHA-256").digest(bytes.toByteArray()));
    } catch (final NoSuchAlgorithmException exception) {
      throw new IllegalStateException("SHA-256 is unavailable", exception);
    }
  }

  private static void writeValues(final DataOutputStream output, final List<String> values)
      throws IOException {
    for (final String value : values) {
      output.writeUTF(value);
    }
  }

  private record RootFiles(
      String kind, String configuredPath, boolean exists, List<Path> members) {}
}
