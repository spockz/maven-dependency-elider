/* WHY: Joins Maven's trace, compiler, bytecode, and dynamic metadata evidence to the per-JAR
 * ProGuard engine while keeping all artifact pointer changes outside the analysis transaction. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.TraceData;
import io.github.spockz.elider.scanner.ArtifactClassIndex;
import io.github.spockz.elider.trimmer.ArchiveSanitizer;
import io.github.spockz.elider.trimmer.ArtifactTrimRecord;
import io.github.spockz.elider.trimmer.DependencyJarTrimmer;
import io.github.spockz.elider.trimmer.JdkApiClassPoolReader;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.TreeSet;
import org.apache.maven.artifact.DependencyResolutionRequiredException;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.project.MavenProject;

/** Creates sanitized outputs for retained dependency JARs without mutating Maven artifacts. */
@SuppressWarnings({
  "PMD.CommentSize",
  "PMD.CouplingBetweenObjects",
  "PMD.GodClass",
  "PMD.TooManyMethods",
  "PMD.CommentDefaultAccessModifier",
  "PMD.NcssCount",
  "PMD.CognitiveComplexity",
  "PMD.CyclomaticComplexity",
  "PMD.UseExplicitTypes",
  "PMD.AvoidInstantiatingObjectsInLoops",
  "PMD.UseConcurrentHashMap",
  "PMD.CompareObjectsWithEquals",
  "PMD.AvoidCatchingGenericException",
  "PMD.ConsecutiveAppendsShouldReuse",
  "PMD.InsufficientStringBufferDeclaration",
  "PMD.ConsecutiveLiteralAppends",
  "PMD.AvoidLiteralsInIfCondition",
  "PMD.CommentRequired",
  "PMD.DataClass",
  "PMD.AvoidFieldNameMatchingMethodName"
})
final class MavenDependencyTrimmer {
  record TrimResult(List<ArtifactTrimRecord> records, int cacheHits, long maximumCacheHitNanos) {
    TrimResult {
      records = List.copyOf(records);
    }
  }

  private MavenDependencyTrimmer() {}

  static TrimResult trim(
      final MavenProject project,
      final MavenSession session,
      final List<MavenElisionService.ArtifactSnapshot> candidates,
      final ArtifactClassIndex classIndex,
      final Set<ArtifactCoordinate> retainedCoordinates,
      final TraceData trace,
      final Set<String> sourceRoots,
      final Set<String> bytecodeRoots,
      final List<String> explicitRoots)
      throws IOException, MojoFailureException {
    final List<String> compileClasspath;
    try {
      compileClasspath = project.getCompileClasspathElements();
    } catch (final DependencyResolutionRequiredException exception) {
      throw new IOException(
          "Cannot resolve the effective compile classpath for JAR trimming", exception);
    }
    final List<String> compilerOptions =
        MavenCompilerSettings.options(project, session, compileClasspath);
    final Path javaHome = Path.of(System.getProperty("java.home")).toAbsolutePath().normalize();
    final int release = releaseFromOptions(compilerOptions, javaHome);
    final var platform = new JdkApiClassPoolReader().read(javaHome, release);

    final Set<String> allRoots = new LinkedHashSet<>(trace.loadedClassesDotFormat());
    allRoots.addAll(sourceRoots);
    allRoots.addAll(bytecodeRoots);
    allRoots.addAll(explicitRoots);
    final Map<io.github.spockz.elider.model.ArtifactFileRef, Set<String>> classesByArtifact =
        classIndex.classesByArtifact();
    final List<MavenElisionService.ArtifactSnapshot> retained =
        candidates.stream()
            .filter(snapshot -> retainedCoordinates.contains(snapshot.coordinate()))
            .toList();
    final List<Path> retainedPaths =
        retained.stream().map(MavenElisionService.ArtifactSnapshot::filePath).toList();
    final Set<Path> distinctOutputs = new HashSet<>();
    final List<ArtifactTrimRecord> records = new ArrayList<>();
    final List<CandidateWork> work = new ArrayList<>();
    for (final MavenElisionService.ArtifactSnapshot candidate : retained) {
      final Path original = candidate.filePath();
      final Set<String> candidateClasses =
          classesByArtifact.entrySet().stream()
              .filter(entry -> entry.getKey().filePath().equals(candidate.filePath()))
              .map(Map.Entry::getValue)
              .findFirst()
              .orElseThrow(
                  () -> new IOException("Missing indexed classes for " + candidate.coordinate()));
      final Set<String> roots = new TreeSet<>();
      for (final String root : allRoots) {
        final String normalized = root.replace('/', '.');
        if (candidateClasses.contains(normalized)) {
          roots.add(normalized);
        }
      }
      for (final String dynamicRoot : DependencyDynamicRoots.read(original)) {
        final String normalized = dynamicRoot.replace('/', '.');
        if (candidateClasses.contains(normalized)) {
          roots.add(normalized);
        }
      }
      final Path output = outputPath(project, candidate.coordinate());
      if (!distinctOutputs.add(output)) {
        throw new IOException(
            "Distinct Maven artifacts map to the same trimmed output path: " + output);
      }
      work.add(new CandidateWork(candidate, candidateClasses, roots, output));
    }

    final Map<String, List<CandidateWork>> ownersByClass = new java.util.HashMap<>();
    int cacheHits = 0;
    long maximumCacheHitNanos = 0L;
    for (final CandidateWork candidate : work) {
      for (final String className : candidate.classes()) {
        ownersByClass.computeIfAbsent(className, ignored -> new ArrayList<>()).add(candidate);
      }
    }
    final DependencyJarTrimmer trimmer = new DependencyJarTrimmer();
    boolean rootsChanged;
    do {
      rootsChanged = false;
      for (final CandidateWork candidate : work) {
        if (candidate.roots().isEmpty()) {
          continue;
        }
        final List<Path> siblings =
            retainedPaths.stream()
                .filter(path -> !path.equals(candidate.snapshot().filePath()))
                .toList();
        final DependencyJarTrimmer.TrimAnalysis analysis =
            trimmer.analyze(candidate.snapshot().filePath(), siblings, platform, candidate.roots());
        candidate.analysis(analysis);
        for (final String linkedName : analysis.reachableLibraryClasses()) {
          final String dottedName = linkedName.replace('/', '.');
          for (final CandidateWork owner : ownersByClass.getOrDefault(dottedName, List.of())) {
            if (owner != candidate && owner.roots().add(dottedName)) {
              rootsChanged = true;
            }
          }
        }
      }
    } while (rootsChanged);

    for (final CandidateWork candidate : work) {
      final DependencyJarTrimmer.TrimAnalysis analysis = candidate.analysis();
      if (analysis == null) {
        continue;
      }
      if (analysis.retainedClasses().size() == analysis.totalClasses()) {
        continue;
      }
      final List<Path> siblings =
          retainedPaths.stream()
              .filter(path -> !path.equals(candidate.snapshot().filePath()))
              .toList();
      final String fingerprint =
          fingerprint(
              candidate.snapshot().filePath(), siblings, candidate.roots(), javaHome, release);
      final Path sidecar =
          candidate.output().resolveSibling(candidate.output().getFileName() + ".cache");
      final ArtifactTrimRecord cached =
          loadCache(
              sidecar,
              candidate.output(),
              candidate.snapshot().filePath(),
              candidate.snapshot().coordinate(),
              fingerprint);
      if (cached != null) {
        cacheHits++;
        maximumCacheHitNanos =
            Math.max(maximumCacheHitNanos, System.nanoTime() - candidate.cachePathStartNanos());
        records.add(cached);
        continue;
      }
      final ArtifactTrimRecord record =
          new ArchiveSanitizer()
              .sanitize(
                  candidate.snapshot().filePath(),
                  candidate.output(),
                  candidate.snapshot().coordinate(),
                  analysis);
      storeCache(sidecar, fingerprint, record);
      records.add(record);
    }
    return new TrimResult(records, cacheHits, maximumCacheHitNanos);
  }

  private static Path outputPath(final MavenProject project, final ArtifactCoordinate coordinate) {
    final String basename =
        safeFilePart(coordinate.groupId())
            + "-"
            + safeFilePart(coordinate.artifactId())
            + "-"
            + safeFilePart(coordinate.version())
            + (coordinate.classifier().isBlank() ? "" : "-" + safeFilePart(coordinate.classifier()))
            + "-trimmed.jar";
    return project.getBuild() == null || project.getBuild().getDirectory() == null
        ? Path.of("target", "elided-artifacts", basename).toAbsolutePath().normalize()
        : Path.of(project.getBuild().getDirectory(), "elided-artifacts", basename)
            .toAbsolutePath()
            .normalize();
  }

  private static final class CandidateWork {
    private final MavenElisionService.ArtifactSnapshot snapshot;
    private final Set<String> classes;
    private final Set<String> roots;
    private final Path output;
    private final long cachePathStartNanos;
    private DependencyJarTrimmer.TrimAnalysis analysis;

    private CandidateWork(
        final MavenElisionService.ArtifactSnapshot snapshot,
        final Set<String> classes,
        final Set<String> roots,
        final Path output) {
      this.snapshot = snapshot;
      this.classes = Set.copyOf(classes);
      this.roots = new TreeSet<>(roots);
      this.output = output;
      this.cachePathStartNanos = System.nanoTime();
    }

    private MavenElisionService.ArtifactSnapshot snapshot() {
      return snapshot;
    }

    private Set<String> classes() {
      return classes;
    }

    private Set<String> roots() {
      return roots;
    }

    private Path output() {
      return output;
    }

    private long cachePathStartNanos() {
      return cachePathStartNanos;
    }

    private DependencyJarTrimmer.TrimAnalysis analysis() {
      return analysis;
    }

    private void analysis(final DependencyJarTrimmer.TrimAnalysis value) {
      analysis = value;
    }
  }

  private static String fingerprint(
      final Path original,
      final List<Path> siblings,
      final Set<String> roots,
      final Path javaHome,
      final int release)
      throws IOException {
    final StringBuilder input = new StringBuilder("release=").append(release).append('\n');
    input.append("original=").append(sha256(original)).append('\n');
    input.append("ct.sym=").append(sha256(javaHome.resolve("lib/ct.sym"))).append('\n');
    final List<Path> orderedLibraries = new ArrayList<>(siblings);
    orderedLibraries.sort(Comparator.comparing(Path::toString));
    for (final Path library : orderedLibraries) {
      input
          .append("library=")
          .append(library.toAbsolutePath().normalize())
          .append(':')
          .append(sha256(library))
          .append('\n');
    }
    for (final String root : new TreeSet<>(roots)) {
      input.append("root=").append(root).append('\n');
    }
    return hash(input.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8));
  }

  private static ArtifactTrimRecord loadCache(
      final Path sidecar,
      final Path output,
      final Path original,
      final ArtifactCoordinate coordinate,
      final String fingerprint)
      throws IOException {
    if (!Files.isRegularFile(sidecar) || !Files.isRegularFile(output)) {
      return null;
    }
    final Properties values = new Properties();
    try (InputStream input = Files.newInputStream(sidecar)) {
      values.load(input);
    }
    if (!fingerprint.equals(values.getProperty("fingerprint"))) {
      return null;
    }
    final String originalSha256 = sha256(original);
    final String trimmedSha256 = values.getProperty("trimmedSha256");
    if (!originalSha256.equals(values.getProperty("originalSha256"))
        || trimmedSha256 == null
        || !trimmedSha256.equals(sha256(output))) {
      return null;
    }
    try {
      return new ArtifactTrimRecord(
          coordinate,
          original.toRealPath(),
          originalSha256,
          values.getProperty("originalSha1"),
          output.toRealPath(),
          trimmedSha256,
          values.getProperty("trimmedSha1"),
          Integer.parseInt(values.getProperty("totalClasses")),
          Integer.parseInt(values.getProperty("retainedClasses")));
    } catch (final RuntimeException exception) {
      return null;
    }
  }

  private static void storeCache(
      final Path sidecar, final String fingerprint, final ArtifactTrimRecord record)
      throws IOException {
    final Properties values = new Properties();
    values.setProperty("fingerprint", fingerprint);
    values.setProperty("originalSha256", record.originalSha256());
    values.setProperty("originalSha1", record.originalSha1());
    values.setProperty("trimmedSha256", record.trimmedSha256());
    values.setProperty("trimmedSha1", record.trimmedSha1());
    values.setProperty("totalClasses", Integer.toString(record.totalClasses()));
    values.setProperty("retainedClasses", Integer.toString(record.retainedClasses()));
    final Path parent = sidecar.getParent();
    if (parent == null) {
      throw new IOException("Trim cache sidecar has no parent directory: " + sidecar);
    }
    final Path temporary = Files.createTempFile(parent, ".trim-cache-", ".tmp");
    try {
      try (var output = Files.newOutputStream(temporary)) {
        values.store(output, null);
      }
      Files.move(
          temporary, sidecar, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
    } finally {
      Files.deleteIfExists(temporary);
    }
  }

  private static String sha256(final Path path) throws IOException {
    try (InputStream input = Files.newInputStream(path)) {
      final MessageDigest digest = MessageDigest.getInstance("SHA-256");
      final byte[] buffer = new byte[8192];
      while (true) {
        final int count = input.read(buffer);
        if (count < 0) {
          return HexFormat.of().formatHex(digest.digest());
        }
        digest.update(buffer, 0, count);
      }
    } catch (final NoSuchAlgorithmException exception) {
      throw new IllegalStateException("SHA-256 is unavailable", exception);
    }
  }

  private static String hash(final byte[] bytes) {
    try {
      return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
    } catch (final NoSuchAlgorithmException exception) {
      throw new IllegalStateException("SHA-256 is unavailable", exception);
    }
  }

  private static int releaseFromOptions(final List<String> options, final Path javaHome)
      throws IOException {
    for (int index = 0; index < options.size() - 1; index++) {
      if ("--release".equals(options.get(index))) {
        final String value = options.get(index + 1);
        return parseRelease(value);
      }
    }
    if (options.contains("-source") && options.contains("-target")) {
      return currentJdkRelease(javaHome);
    }
    throw new IOException("Cannot determine effective Java compiler release for JAR trimming");
  }

  private static int parseRelease(final String value) throws IOException {
    final String normalized = value.startsWith("1.") ? value.substring(2) : value;
    try {
      return Integer.parseInt(normalized);
    } catch (final NumberFormatException exception) {
      throw new IOException("Unsupported Java compiler release: " + value, exception);
    }
  }

  private static int currentJdkRelease(final Path javaHome) throws IOException {
    final Path releaseFile = javaHome.resolve("release");
    if (!Files.isRegularFile(releaseFile)) {
      throw new IOException("Cannot identify the executing JDK release: " + javaHome);
    }
    for (final String line : Files.readAllLines(releaseFile)) {
      if (line.startsWith("JAVA_VERSION=\"")) {
        final String version = line.substring("JAVA_VERSION=\"".length()).replace("\"", "");
        final int dot = version.indexOf('.');
        final String feature = dot < 0 ? version : version.substring(0, dot);
        try {
          return Integer.parseInt(feature);
        } catch (final NumberFormatException exception) {
          throw new IOException("Unsupported executing JDK version: " + version, exception);
        }
      }
    }
    throw new IOException("Cannot identify the executing JDK release: " + javaHome);
  }

  private static String safeFilePart(final String value) {
    if (value == null || value.isBlank()) {
      return "unnamed";
    }
    return value.replaceAll("[^A-Za-z0-9._-]", "_");
  }
}
