/* WHY: Joins Maven's trace, compiler, bytecode, and dynamic metadata evidence to the per-JAR
 * ProGuard engine while keeping all artifact pointer changes outside the analysis transaction. */

package io.github.spockz.elider.plugin;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.TraceData;
import io.github.spockz.elider.scanner.ArtifactClassIndex;
import io.github.spockz.elider.trimmer.ArchiveSanitizer;
import io.github.spockz.elider.trimmer.ArtifactTrimRecord;
import io.github.spockz.elider.trimmer.DependencyJarTrimmer;
import io.github.spockz.elider.trimmer.JdkApiClassPoolReader;
import io.github.spockz.elider.trimmer.TrimAnalysisSession;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.jar.JarFile;
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
  "PMD.InsufficientStringBufferDeclaration",
  "PMD.AvoidLiteralsInIfCondition",
  "PMD.CommentRequired",
  "PMD.DataClass",
  "PMD.AvoidFieldNameMatchingMethodName"
})
final class MavenDependencyTrimmer {
  private static final String ELIDED_ARTIFACTS = "elided-artifacts";
  private static final Set<String> TRIMMABLE_SCOPES = Set.of("compile", "runtime");
  private static final ObjectMapper JSON = new ObjectMapper();
  private static final int CACHE_SCHEMA_VERSION = 8;
  private static final String ENGINE_VERSION = "proguard-core-9.1.10";

  record TrimResult(
      List<ArtifactTrimRecord> records,
      List<ArtifactCoordinate> multiReleasePassthroughArtifacts,
      List<ArtifactCoordinate> moduleInfoPassthroughArtifacts,
      List<ArtifactCoordinate> configuredPassThroughArtifacts,
      int cacheHits,
      long maximumCacheHitNanos,
      int analysisRuns) {
    TrimResult {
      records = List.copyOf(records);
      multiReleasePassthroughArtifacts = List.copyOf(multiReleasePassthroughArtifacts);
      moduleInfoPassthroughArtifacts = List.copyOf(moduleInfoPassthroughArtifacts);
      configuredPassThroughArtifacts = List.copyOf(configuredPassThroughArtifacts);
    }
  }

  record ScanInputs(
      ArtifactClassIndex classIndex, Map<Path, DependencyDynamicRoots.RootScan> dynamicRootScans) {}

  private record CacheManifest(String fingerprint, List<CacheEntry> entries) {}

  private record CacheEntry(
      String originalPath,
      String originalSha256,
      String originalSha1,
      String trimmedPath,
      String trimmedSha256,
      String trimmedSha1,
      int totalClasses,
      int retainedClasses,
      Set<String> roots,
      Set<String> retainedClassNames,
      Set<String> reachableLibraryClasses) {}

  record TrimRequest(
      MavenProject project,
      MavenSession session,
      List<MavenElisionService.ArtifactSnapshot> candidates,
      ScanInputs scanInputs,
      Set<ArtifactCoordinate> retainedCoordinates,
      TraceData trace,
      Set<String> sourceRoots,
      Set<String> bytecodeRoots,
      List<String> explicitRoots,
      boolean failOnUnsupportedMultiRelease,
      List<String> explicitPassThroughCoordinates,
      boolean failOnUnsupportedModuleInfo) {}

  private MavenDependencyTrimmer() {}

  static TrimResult trim(final TrimRequest request) throws IOException, MojoFailureException {
    final MavenProject project = request.project();
    final MavenSession session = request.session();
    final List<MavenElisionService.ArtifactSnapshot> candidates = request.candidates();
    final ScanInputs scanInputs = request.scanInputs();
    final Set<ArtifactCoordinate> retainedCoordinates = request.retainedCoordinates();
    final TraceData trace = request.trace();
    final Set<String> sourceRoots = request.sourceRoots();
    final Set<String> bytecodeRoots = request.bytecodeRoots();
    final List<String> explicitRoots = request.explicitRoots();
    final boolean failOnUnsupportedMultiRelease = request.failOnUnsupportedMultiRelease();
    final List<String> explicitPassThroughCoordinates = request.explicitPassThroughCoordinates();
    final boolean failOnUnsupportedModuleInfo = request.failOnUnsupportedModuleInfo();
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

    final Set<String> allRoots = new LinkedHashSet<>(trace.loadedClassesDotFormat());
    allRoots.addAll(sourceRoots);
    allRoots.addAll(bytecodeRoots);
    allRoots.addAll(explicitRoots);
    final Map<io.github.spockz.elider.model.ArtifactFileRef, Set<String>> classesByArtifact =
        scanInputs.classIndex().classesByArtifact();
    final List<MavenElisionService.ArtifactSnapshot> retainedLibraries =
        candidates.stream()
            .filter(
                snapshot ->
                    "jar".equals(snapshot.coordinate().type())
                        && TRIMMABLE_SCOPES.contains(snapshot.coordinate().scope())
                        && retainedCoordinates.contains(snapshot.coordinate()))
            .toList();
    final List<MavenElisionService.ArtifactSnapshot> multiReleasePassthrough = new ArrayList<>();
    final List<MavenElisionService.ArtifactSnapshot> moduleInfoPassthrough = new ArrayList<>();
    for (final MavenElisionService.ArtifactSnapshot snapshot : retainedLibraries) {
      if (MultiReleaseLibraryProjection.hasUnsupportedVersionedClasses(snapshot.filePath())) {
        if (failOnUnsupportedMultiRelease) {
          throw new IOException(
              "Unsupported multi-release implementation classes in " + snapshot.coordinate());
        }
        multiReleasePassthrough.add(snapshot);
      }
      if (MultiReleaseLibraryProjection.hasRootModuleDescriptor(snapshot.filePath())) {
        if (failOnUnsupportedModuleInfo) {
          throw new IOException(
              "Unsupported root module descriptor in retained classpath JAR: "
                  + snapshot.coordinate());
        }
        moduleInfoPassthrough.add(snapshot);
      }
    }
    final List<MavenElisionService.ArtifactSnapshot> configuredPassThrough =
        parsePassThroughArtifacts(explicitPassThroughCoordinates, retainedLibraries);
    final Set<String> multiReleaseIdentities = identities(multiReleasePassthrough);
    final Set<String> moduleInfoIdentities = identities(moduleInfoPassthrough);
    final List<MavenElisionService.ArtifactSnapshot> configuredNonMrPassThrough =
        configuredPassThrough.stream()
            .filter(
                snapshot ->
                    !multiReleaseIdentities.contains(artifactIdentity(snapshot.coordinate()))
                        && !moduleInfoIdentities.contains(artifactIdentity(snapshot.coordinate())))
            .toList();
    final Set<String> skippedArtifactIdentities = new LinkedHashSet<>(multiReleaseIdentities);
    skippedArtifactIdentities.addAll(moduleInfoIdentities);
    skippedArtifactIdentities.addAll(identities(configuredPassThrough));
    final List<ArtifactCoordinate> multiReleasePassthroughCoordinates =
        multiReleasePassthrough.stream()
            .map(MavenElisionService.ArtifactSnapshot::coordinate)
            .toList();
    final List<ArtifactCoordinate> moduleInfoPassthroughCoordinates =
        moduleInfoPassthrough.stream()
            .map(MavenElisionService.ArtifactSnapshot::coordinate)
            .toList();
    final List<ArtifactCoordinate> configuredPassThroughCoordinates =
        configuredNonMrPassThrough.stream()
            .map(MavenElisionService.ArtifactSnapshot::coordinate)
            .toList();
    final List<Path> retainedInputPaths =
        retainedLibraries.stream().map(MavenElisionService.ArtifactSnapshot::filePath).toList();
    final List<MavenElisionService.ArtifactSnapshot> retained =
        retainedLibraries.stream()
            .filter(
                snapshot ->
                    !skippedArtifactIdentities.contains(artifactIdentity(snapshot.coordinate())))
            .toList();
    final Set<Path> distinctOutputs = new HashSet<>();
    final List<ArtifactTrimRecord> records = new ArrayList<>();
    final List<CandidateWork> work = new ArrayList<>();
    final Set<String> retainedDynamicRoots = new HashSet<>();
    for (final MavenElisionService.ArtifactSnapshot snapshot : retainedLibraries) {
      final DependencyDynamicRoots.RootScan scan =
          scanInputs.dynamicRootScans().get(snapshot.filePath());
      if (scan == null) {
        throw new IOException(
            "Missing dynamic-root scan for retained artifact " + snapshot.coordinate());
      }
      retainedDynamicRoots.addAll(scan.roots());
    }
    for (final MavenElisionService.ArtifactSnapshot candidate : retained) {
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
      for (final String dynamicRoot : retainedDynamicRoots) {
        final String normalized = dynamicRoot.replace('/', '.');
        if (candidateClasses.contains(normalized)) {
          roots.add(normalized);
        }
      }
      if (candidateClasses.isEmpty()) {
        continue;
      }
      final Path output = outputPath(project, candidate.coordinate());
      if (!distinctOutputs.add(output)) {
        throw new IOException(
            "Distinct Maven artifacts map to the same trimmed output path: " + output);
      }
      work.add(new CandidateWork(candidate, candidateClasses, roots, output));
    }

    final Map<String, List<CandidateWork>> ownersByClass = new java.util.HashMap<>();
    final Map<String, Path> ownerByClass = new java.util.HashMap<>();
    for (final CandidateWork candidate : work) {
      for (final String className : candidate.classes()) {
        final Path previous = ownerByClass.putIfAbsent(className, candidate.snapshot().filePath());
        if (previous != null && !previous.equals(candidate.snapshot().filePath())) {
          throw new IOException(
              "Duplicate class across retained dependency JARs makes library order ambiguous: "
                  + className);
        }
        ownersByClass.computeIfAbsent(className, ignored -> new ArrayList<>()).add(candidate);
      }
    }
    final Path cacheManifestPath =
        project.getBuild() == null || project.getBuild().getDirectory() == null
            ? Path.of("target", ELIDED_ARTIFACTS, ".trim-analysis-cache.json")
                .toAbsolutePath()
                .normalize()
            : Path.of(
                    project.getBuild().getDirectory(),
                    ELIDED_ARTIFACTS,
                    ".trim-analysis-cache.json")
                .toAbsolutePath()
                .normalize();
    final long cacheStart = System.nanoTime();
    final int runtimeRelease = Runtime.version().feature();
    final String completeFingerprint =
        fingerprint(
            work,
            retainedInputPaths,
            skippedArtifactIdentities,
            runtimeRelease,
            javaHome,
            release,
            CACHE_SCHEMA_VERSION,
            ENGINE_VERSION);
    final TrimResult cached =
        loadCache(
            cacheManifestPath,
            completeFingerprint,
            work,
            multiReleasePassthroughCoordinates,
            moduleInfoPassthroughCoordinates,
            configuredPassThroughCoordinates,
            cacheStart);
    if (cached != null) {
      return cached;
    }
    final Path analysisLibraryDirectory =
        project.getBuild() == null || project.getBuild().getDirectory() == null
            ? Path.of("target", ELIDED_ARTIFACTS, ".analysis-libraries")
                .toAbsolutePath()
                .normalize()
            : Path.of(project.getBuild().getDirectory(), ELIDED_ARTIFACTS, ".analysis-libraries")
                .toAbsolutePath()
                .normalize();
    final List<Path> analysisLibraries = new ArrayList<>();
    final List<SkippedProgram> skippedPrograms = new ArrayList<>();
    for (final MavenElisionService.ArtifactSnapshot snapshot : retainedLibraries) {
      if (skippedArtifactIdentities.contains(artifactIdentity(snapshot.coordinate()))) {
        final boolean multiRelease =
            multiReleaseIdentities.contains(artifactIdentity(snapshot.coordinate()));
        final boolean rootModuleDescriptor =
            MultiReleaseLibraryProjection.hasRootModuleDescriptor(snapshot.filePath());
        final Path analysisPath =
            multiRelease || rootModuleDescriptor
                ? MultiReleaseLibraryProjection.create(
                    snapshot.filePath(),
                    snapshot.coordinate(),
                    analysisLibraryDirectory,
                    runtimeRelease)
                : snapshot.filePath();
        analysisLibraries.add(analysisPath);
        skippedPrograms.add(new SkippedProgram(analysisPath, classNames(analysisPath)));
      } else {
        analysisLibraries.add(snapshot.filePath());
      }
    }
    final Set<String> unchangedPassThroughClassNames = new LinkedHashSet<>();
    skippedPrograms.stream()
        .flatMap(program -> program.classNames().stream())
        .forEach(unchangedPassThroughClassNames::add);
    for (final SkippedProgram skippedProgram : skippedPrograms) {
      for (final Path siblingPath : analysisLibraries) {
        if (siblingPath.equals(skippedProgram.path())) {
          continue;
        }
        final Set<String> ambiguousNames = new HashSet<>(skippedProgram.classNames());
        ambiguousNames.retainAll(classNames(siblingPath));
        if (!ambiguousNames.isEmpty()) {
          throw new IOException(
              "Duplicate class ownership makes pass-through unresolved-link tolerance ambiguous: "
                  + ambiguousNames);
        }
      }
    }
    final var platform = new JdkApiClassPoolReader().read(javaHome, release);
    final var runtimePlatform =
        runtimeRelease == release
            ? platform
            : new JdkApiClassPoolReader().read(javaHome, runtimeRelease);
    final DependencyJarTrimmer trimmer = new DependencyJarTrimmer();
    final var analysisSession = new TrimAnalysisSession(trimmer);
    final Set<String> allCandidateClasses = new HashSet<>(ownerByClass.keySet());
    for (final SkippedProgram skippedProgram : skippedPrograms) {
      for (final String className : skippedProgram.classNames()) {
        if (!allCandidateClasses.add(className)) {
          throw new IOException(
              "Duplicate class across retained dependency JARs makes library order ambiguous: "
                  + className);
        }
      }
    }
    int analysisRuns = 0;
    for (final SkippedProgram skippedProgram : skippedPrograms) {
      final List<Path> siblings =
          analysisLibraries.stream().filter(path -> !path.equals(skippedProgram.path())).toList();
      final DependencyJarTrimmer.TrimAnalysis analysis =
          analysisSession.analyzeUnchangedPassThrough(
              skippedProgram.path(),
              siblings,
              runtimePlatform,
              skippedProgram.classNames(),
              unchangedPassThroughClassNames);
      analysisRuns++;
      for (final String linkedName : analysis.reachableLibraryClasses()) {
        final String dottedName = linkedName.replace('/', '.');
        for (final CandidateWork owner : ownersByClass.getOrDefault(dottedName, List.of())) {
          owner.roots().add(dottedName);
        }
      }
    }
    boolean rootsChanged;
    do {
      rootsChanged = false;
      for (final CandidateWork candidate : work) {
        final List<Path> siblings =
            analysisLibraries.stream()
                .filter(path -> !path.equals(candidate.snapshot().filePath()))
                .toList();
        final DependencyJarTrimmer.TrimAnalysis analysis =
            analysisSession.analyzeWithUnchangedPassThroughLibraries(
                candidate.snapshot().filePath(),
                siblings,
                platform,
                candidate.roots(),
                unchangedPassThroughClassNames);
        analysisRuns++;
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

    final List<CacheEntry> cacheEntries = new ArrayList<>();
    for (final CandidateWork candidate : work) {
      final DependencyJarTrimmer.TrimAnalysis analysis = candidate.analysis();
      if (analysis == null) {
        continue;
      }
      if (analysis.retainedClasses().size() == analysis.totalClasses()) {
        cacheEntries.add(cacheEntry(candidate, null));
        continue;
      }
      final ArtifactTrimRecord record =
          new ArchiveSanitizer()
              .sanitize(
                  candidate.snapshot().filePath(),
                  candidate.output(),
                  candidate.snapshot().coordinate(),
                  analysis);
      records.add(record);
      cacheEntries.add(cacheEntry(candidate, record));
    }
    storeCache(cacheManifestPath, new CacheManifest(completeFingerprint, cacheEntries));
    return new TrimResult(
        records,
        multiReleasePassthroughCoordinates,
        moduleInfoPassthroughCoordinates,
        configuredPassThroughCoordinates,
        0,
        0L,
        analysisRuns);
  }

  private static Set<String> classNames(final Path archivePath) throws IOException {
    final Set<String> classNames = new TreeSet<>();
    try (JarFile archive = new JarFile(archivePath.toFile())) {
      final var entries = archive.entries();
      while (entries.hasMoreElements()) {
        final String name = entries.nextElement().getName();
        if (name.endsWith(".class")
            && !"module-info.class".equals(name)
            && !name.endsWith("/module-info.class")) {
          classNames.add(name.substring(0, name.length() - ".class".length()).replace('/', '.'));
        }
      }
    }
    return Set.copyOf(classNames);
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
        ? Path.of("target", ELIDED_ARTIFACTS, basename).toAbsolutePath().normalize()
        : Path.of(project.getBuild().getDirectory(), ELIDED_ARTIFACTS, basename)
            .toAbsolutePath()
            .normalize();
  }

  private static final class CandidateWork {
    private final MavenElisionService.ArtifactSnapshot snapshot;
    private final Set<String> classes;
    private final Set<String> roots;
    private final Path output;
    private DependencyJarTrimmer.TrimAnalysis analysis;

    private CandidateWork(
        final MavenElisionService.ArtifactSnapshot snapshot,
        final Set<String> classes,
        final Set<String> roots,
        final Path output) {
      this.snapshot = snapshot;
      this.classes = Set.copyOf(classes);
      this.roots = new TreeSet<>(roots.isEmpty() ? classes : roots);
      this.output = output;
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

    private DependencyJarTrimmer.TrimAnalysis analysis() {
      return analysis;
    }

    private void analysis(final DependencyJarTrimmer.TrimAnalysis value) {
      analysis = value;
    }
  }

  private record SkippedProgram(Path path, Set<String> classNames) {
    private SkippedProgram {
      classNames = Set.copyOf(classNames);
    }
  }

  private static String fingerprint(
      final List<CandidateWork> candidates,
      final List<Path> allRetainedInputs,
      final Set<String> skippedArtifactIdentities,
      final int runtimeRelease,
      final Path javaHome,
      final int release,
      final int schemaVersion,
      final String engineVersion)
      throws IOException {
    final List<String> candidateIdentities = new ArrayList<>();
    final Set<String> roots = new TreeSet<>();
    for (final CandidateWork candidate : candidates) {
      candidateIdentities.add(
          candidate.snapshot().coordinate()
              + ":"
              + candidate.snapshot().filePath().toAbsolutePath().normalize());
      roots.addAll(candidate.roots());
    }
    candidateIdentities.addAll(
        skippedArtifactIdentities.stream()
            .sorted()
            .map(identity -> "trim-skip:" + identity)
            .toList());
    candidateIdentities.add("runtime-release:" + runtimeRelease);
    final Set<Path> platformInputs = new LinkedHashSet<>(platformInputs(javaHome, release));
    if (runtimeRelease != release) {
      platformInputs.addAll(platformInputs(javaHome, runtimeRelease));
    }
    return fingerprintForInputs(
        candidateIdentities,
        allRetainedInputs,
        roots,
        List.copyOf(platformInputs),
        release,
        schemaVersion,
        engineVersion);
  }

  private static String artifactIdentity(final ArtifactCoordinate coordinate) {
    return coordinate.groupId()
        + ":"
        + coordinate.artifactId()
        + ":"
        + coordinate.version()
        + ":"
        + coordinate.type()
        + ":"
        + coordinate.classifier();
  }

  private static Set<String> identities(
      final List<MavenElisionService.ArtifactSnapshot> snapshots) {
    return snapshots.stream()
        .map(snapshot -> artifactIdentity(snapshot.coordinate()))
        .collect(java.util.stream.Collectors.toCollection(LinkedHashSet::new));
  }

  private static List<MavenElisionService.ArtifactSnapshot> parsePassThroughArtifacts(
      final List<String> requested,
      final List<MavenElisionService.ArtifactSnapshot> retainedLibraries)
      throws IOException {
    final Set<String> requestedIdentities = new LinkedHashSet<>();
    for (final String raw : requested) {
      if (raw == null || raw.isBlank()) {
        throw new IOException("elide.trimSkipArtifacts must not contain blank coordinates");
      }
      final String[] parts = raw.trim().split(":", -1);
      if (parts.length < 3
          || parts.length > 5
          || parts[0].isBlank()
          || parts[1].isBlank()
          || parts[2].isBlank()) {
        throw new IOException(
            "Invalid elide.trimSkipArtifacts coordinate; expected "
                + "group:artifact:version[:type[:classifier]]: "
                + raw);
      }
      final String groupId = parts[0];
      final String artifactId = parts[1];
      final String version = parts[2];
      final String type = parts.length > 3 && !parts[3].isBlank() ? parts[3] : "jar";
      final String classifier = parts.length > 4 ? parts[4] : "";
      final List<MavenElisionService.ArtifactSnapshot> matches =
          retainedLibraries.stream()
              .filter(
                  snapshot -> {
                    final ArtifactCoordinate coordinate = snapshot.coordinate();
                    return coordinate.groupId().equals(groupId)
                        && coordinate.artifactId().equals(artifactId)
                        && coordinate.version().equals(version)
                        && coordinate.type().equals(type)
                        && coordinate.classifier().equals(classifier);
                  })
              .toList();
      if (matches.isEmpty()) {
        throw new IOException(
            "elide.trimSkipArtifacts coordinate is not a retained compile/runtime JAR: " + raw);
      }
      matches.stream()
          .map(snapshot -> artifactIdentity(snapshot.coordinate()))
          .forEach(requestedIdentities::add);
    }
    return retainedLibraries.stream()
        .filter(snapshot -> requestedIdentities.contains(artifactIdentity(snapshot.coordinate())))
        .toList();
  }

  static String fingerprintForInputs(
      final List<String> candidateIdentities,
      final List<Path> orderedLibraries,
      final Set<String> roots,
      final List<Path> platformInputs,
      final int release,
      final int schemaVersion,
      final String engineVersion)
      throws IOException {
    final StringBuilder input =
        new StringBuilder("release=")
            .append(release)
            .append("\nschema=")
            .append(schemaVersion)
            .append("\nengine=")
            .append(engineVersion)
            .append('\n');
    for (final String candidateIdentity : candidateIdentities) {
      input.append("candidate=").append(candidateIdentity).append('\n');
    }
    for (final String root : new TreeSet<>(roots)) {
      input.append("root=").append(root).append('\n');
    }
    for (int index = 0; index < orderedLibraries.size(); index++) {
      final Path library = orderedLibraries.get(index);
      input
          .append("library[")
          .append(index)
          .append("]=")
          .append(library.toAbsolutePath().normalize())
          .append(':')
          .append(sha256(library))
          .append('\n');
    }
    for (final Path platformInput : platformInputs) {
      input
          .append("platform=")
          .append(platformInput.getFileName())
          .append(':')
          .append(sha256(platformInput))
          .append('\n');
    }
    return hash(input.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8));
  }

  private static List<Path> platformInputs(final Path javaHome, final int release)
      throws IOException {
    final Path ctSym = javaHome.resolve("lib/ct.sym");
    if (!Files.isRegularFile(ctSym)) {
      throw new IOException("The selected JDK does not provide lib/ct.sym: " + ctSym);
    }
    final String releaseCode =
        release <= 9 ? Integer.toString(release) : Character.toString((char) ('A' + release - 10));
    try (java.util.zip.ZipFile archive = new java.util.zip.ZipFile(ctSym.toFile())) {
      final var entries = archive.entries();
      while (entries.hasMoreElements()) {
        final String[] parts = entries.nextElement().getName().split("/", 3);
        if (parts.length == 3 && parts[0].contains(releaseCode) && parts[2].endsWith(".sig")) {
          return List.of(ctSym);
        }
      }
    }
    final Path jmods = javaHome.resolve("jmods");
    if (!Files.isDirectory(jmods)) {
      throw new IOException("The selected JDK has no jmods directory: " + jmods);
    }
    try (var paths = Files.list(jmods)) {
      final List<Path> modules =
          paths.filter(path -> path.toString().endsWith(".jmod")).sorted().toList();
      if (modules.isEmpty()) {
        throw new IOException("No JDK platform signatures found for release " + release);
      }
      return modules;
    }
  }

  private static CacheEntry cacheEntry(
      final CandidateWork candidate, final ArtifactTrimRecord record) throws IOException {
    final DependencyJarTrimmer.TrimAnalysis analysis = candidate.analysis();
    return new CacheEntry(
        candidate.snapshot().filePath().toAbsolutePath().normalize().toString(),
        sha256(candidate.snapshot().filePath()),
        record == null ? null : record.originalSha1(),
        record == null ? null : record.trimmedPath().toString(),
        record == null ? null : record.trimmedSha256(),
        record == null ? null : record.trimmedSha1(),
        analysis.totalClasses(),
        analysis.retainedClasses().size(),
        candidate.roots(),
        analysis.retainedClasses(),
        analysis.reachableLibraryClasses());
  }

  private static TrimResult loadCache(
      final Path manifestPath,
      final String fingerprint,
      final List<CandidateWork> candidates,
      final List<ArtifactCoordinate> multiReleasePassthroughArtifacts,
      final List<ArtifactCoordinate> moduleInfoPassthroughArtifacts,
      final List<ArtifactCoordinate> configuredPassThroughArtifacts,
      final long started)
      throws IOException {
    if (!Files.isRegularFile(manifestPath)) {
      return null;
    }
    final CacheManifest manifest;
    try {
      manifest = JSON.readValue(manifestPath.toFile(), CacheManifest.class);
    } catch (final IOException exception) {
      return null;
    }
    if (manifest == null
        || manifest.entries() == null
        || !fingerprint.equals(manifest.fingerprint())
        || manifest.entries().size() != candidates.size()) {
      return null;
    }
    final List<ArtifactTrimRecord> records = new ArrayList<>();
    for (int index = 0; index < candidates.size(); index++) {
      final CandidateWork candidate = candidates.get(index);
      final CacheEntry entry = manifest.entries().get(index);
      final Path original = candidate.snapshot().filePath().toAbsolutePath().normalize();
      if (!validCacheEntry(entry, candidate)) {
        return null;
      }
      if (!original.toString().equals(entry.originalPath())
          || !sha256(original).equals(entry.originalSha256())) {
        return null;
      }
      if (entry.trimmedPath() == null) {
        continue;
      }
      final Path output = candidate.output().toAbsolutePath().normalize();
      if (!output.toString().equals(entry.trimmedPath())
          || !Files.isRegularFile(output)
          || !entry.trimmedSha256().equals(sha256(output))) {
        return null;
      }
      records.add(
          new ArtifactTrimRecord(
              candidate.snapshot().coordinate(),
              original.toRealPath(),
              entry.originalSha256(),
              entry.originalSha1(),
              output.toRealPath(),
              entry.trimmedSha256(),
              entry.trimmedSha1(),
              entry.totalClasses(),
              entry.retainedClasses()));
    }
    return new TrimResult(
        records,
        multiReleasePassthroughArtifacts,
        moduleInfoPassthroughArtifacts,
        configuredPassThroughArtifacts,
        records.size(),
        System.nanoTime() - started,
        0);
  }

  private static boolean validCacheEntry(final CacheEntry entry, final CandidateWork candidate) {
    if (entry == null
        || !validDigest(entry.originalSha256(), 64)
        || entry.roots() == null
        || entry.roots().contains(null)
        || entry.retainedClassNames() == null
        || entry.retainedClassNames().contains(null)
        || entry.reachableLibraryClasses() == null
        || entry.reachableLibraryClasses().contains(null)
        || entry.totalClasses() != candidate.classes().size()
        || entry.retainedClasses() < 0
        || entry.retainedClasses() > entry.totalClasses()
        || entry.retainedClassNames().size() != entry.retainedClasses()
        || !candidate.classes().containsAll(entry.roots())) {
      return false;
    }
    for (final String retainedClass : entry.retainedClassNames()) {
      if (!candidate.classes().contains(retainedClass.replace('/', '.'))) {
        return false;
      }
    }
    if (entry.trimmedPath() == null) {
      return entry.retainedClasses() == entry.totalClasses()
          && entry.originalSha1() == null
          && entry.trimmedSha256() == null
          && entry.trimmedSha1() == null;
    }
    return validDigest(entry.originalSha1(), 40)
        && validDigest(entry.trimmedSha256(), 64)
        && validDigest(entry.trimmedSha1(), 40)
        && entry.retainedClasses() < entry.totalClasses();
  }

  private static boolean validDigest(final String value, final int length) {
    return value != null && value.matches("[0-9a-f]{" + length + "}");
  }

  private static void storeCache(final Path manifestPath, final CacheManifest manifest)
      throws IOException {
    final Path parent = manifestPath.getParent();
    if (parent == null) {
      throw new IOException("Trim cache manifest has no parent directory: " + manifestPath);
    }
    Files.createDirectories(parent);
    final Path temporary = Files.createTempFile(parent, ".trim-cache-", ".json.tmp");
    try {
      JSON.writeValue(temporary.toFile(), manifest);
      Files.move(
          temporary,
          manifestPath,
          StandardCopyOption.REPLACE_EXISTING,
          StandardCopyOption.ATOMIC_MOVE);
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
