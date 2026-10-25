// WHY: Adapts Maven artifacts into the shared pruning pipeline and prepares a checked plan.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.engine.ClassUsageReport;
import io.github.spockz.elider.engine.DependencyPruner;
import io.github.spockz.elider.engine.PruneConfig;
import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.ArtifactFileRef;
import io.github.spockz.elider.model.ElisionDecision;
import io.github.spockz.elider.model.TraceData;
import io.github.spockz.elider.scanner.ArtifactClassIndex;
import io.github.spockz.elider.scanner.BytecodeReferenceScan;
import io.github.spockz.elider.scanner.JarIndexScanner;
import io.github.spockz.elider.scanner.ProductionBytecodeReferenceScanner;
import io.github.spockz.elider.trace.CompositeTraceReader;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.artifact.DependencyResolutionRequiredException;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.model.Plugin;
import org.apache.maven.model.PluginExecution;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.project.MavenProject;

/** Coordinates shared trace analysis and a nonmutating Maven artifact plan. */
@SuppressWarnings({
  "PMD.ExcessiveImports",
  "PMD.LawOfDemeter",
  "PMD.CouplingBetweenObjects",
  "PMD.GodClass",
  "PMD.CyclomaticComplexity",
  "PMD.TooManyMethods",
  "PMD.CommentDefaultAccessModifier",
  "PMD.AvoidDuplicateLiterals"
})
final class MavenElisionService {
  /** Maven scopes that may be considered for whole-artifact elision. */
  private static final Set<String> ELIGIBLE_SCOPES = Set.of("compile", "runtime");

  /** Dependency scopes Maven can place on its production compile classpath. */
  private static final Set<String> COMPILE_VISIBLE_SCOPES = Set.of("compile", "provided", "system");

  /** Creates the stateless Maven adapter. */
  MavenElisionService() {
    super();
  }

  /** Analyzes the complete resolved set while scanning only real JAR artifacts. */
  Analysis analyze(
      final MavenProject project,
      final List<File> traceFiles,
      final List<String> excludedArtifacts,
      final File productionOutput)
      throws IOException, MojoFailureException {
    return analyze(project, traceFiles, excludedArtifacts, productionOutput, null, false);
  }

  Analysis analyze(
      final MavenProject project,
      final List<File> traceFiles,
      final List<String> excludedArtifacts,
      final File productionOutput,
      final MavenSession session)
      throws IOException, MojoFailureException {
    return analyze(project, traceFiles, excludedArtifacts, productionOutput, session, false);
  }

  Analysis analyze(
      final MavenProject project,
      final List<File> traceFiles,
      final List<String> excludedArtifacts,
      final File productionOutput,
      final MavenSession session,
      final boolean sourceRootsComplete)
      throws IOException, MojoFailureException {
    final List<Artifact> resolved = new ArrayList<>(project.getArtifacts());
    final List<ArtifactSnapshot> resolvedSnapshots = snapshots(resolved);
    validateIdentityPaths(resolvedSnapshots);
    final Set<Artifact> directView = project.getDependencyArtifacts();
    final boolean directPresent = directView != null;
    final List<Artifact> direct = directPresent ? new ArrayList<>(directView) : List.of();
    final List<ArtifactSnapshot> directSnapshots = snapshots(direct);
    validateIdentityPaths(directSnapshots);
    final List<ArtifactFileRef> scanCandidates = new ArrayList<>();
    for (final ArtifactSnapshot snapshot : resolvedSnapshots) {
      if (isJarCandidate(snapshot)) {
        scanCandidates.add(ArtifactFileRef.fromPath(snapshot.coordinate(), snapshot.filePath()));
      }
    }
    final TraceData trace = new CompositeTraceReader().readAll(toPaths(traceFiles));
    final ArtifactClassIndex index = new JarIndexScanner().scan(scanCandidates);
    final CompilerInputs compilerInputs =
        compilerInputs(project, session, scanCandidates, index, sourceRootsComplete);
    final Optional<BytecodeReferenceScan> bytecodeScan =
        productionOutput == null
            ? Optional.empty()
            : Optional.of(new ProductionBytecodeReferenceScanner().scan(productionOutput.toPath()));
    final ClassUsageReport classUsageReport = ClassUsageReport.classify(index, trace, bytecodeScan);
    final ElisionDecision decision =
        new DependencyPruner()
            .prune(
                scanCandidates,
                index,
                trace,
                config(excludedArtifacts, compilerInputs.compileVisibleCoordinates()),
                compilerInputs.requiredClasses());
    return new Analysis(
        resolvedSnapshots,
        directPresent,
        directSnapshots,
        decision,
        classUsageReport,
        bytecodeScan);
  }

  /** Prepares Maven artifact views without mutating project state. */
  ApplyPlan plan(final MavenProject project, final Analysis analysis) throws IOException {
    final Set<ArtifactIdentity> elided = identities(analysis.decision().elidedArtifacts());
    final Set<ArtifactIdentity> retained = identities(analysis.decision().retainedArtifacts());
    retained.retainAll(elided);
    if (!retained.isEmpty()) {
      throw new IOException("Contradictory retained and elided artifact identities: " + retained);
    }
    final List<Artifact> resolvedInput = new ArrayList<>(project.getArtifacts());
    validateCurrentView("resolved", resolvedInput, analysis.resolvedSnapshots());
    final Set<Artifact> directSet = project.getDependencyArtifacts();
    final boolean directViewPresent = directSet != null;
    if (directViewPresent != analysis.directArtifactsPresent()) {
      throw new IOException("Maven direct artifact view presence changed after analysis");
    }
    final List<Artifact> directInput = directSet == null ? List.of() : new ArrayList<>(directSet);
    validateCurrentView("direct", directInput, analysis.directSnapshots());
    validateIdentityPaths(analysis.resolvedSnapshots());
    validateIdentityPaths(analysis.directSnapshots());
    validateDirectPaths(analysis.resolvedSnapshots(), analysis.directSnapshots());
    return new ApplyPlan(
        retained(resolvedInput, elided),
        analysis.directArtifactsPresent(),
        retained(directInput, elided));
  }

  static List<ArtifactSnapshot> snapshots(final Collection<Artifact> artifacts) {
    return artifacts.stream().map(ArtifactSnapshot::from).toList();
  }

  @SuppressWarnings({
    "PMD.CyclomaticComplexity",
    "PMD.AvoidDuplicateLiterals",
    "PMD.CompareObjectsWithEquals"
  })
  private static void validateCurrentView(
      final String viewName, final List<Artifact> current, final List<ArtifactSnapshot> snapshots)
      throws IOException {
    if (current.size() != snapshots.size()) {
      throw new IOException("Maven " + viewName + " artifact view size changed after analysis");
    }
    for (int index = 0; index < current.size(); index++) {
      final Artifact artifact = current.get(index);
      final ArtifactSnapshot snapshot = snapshots.get(index);
      if (artifact != snapshot.artifact()) {
        throw new IOException(
            "Maven " + viewName + " artifact order or reference changed after analysis");
      }
      if (!snapshot.coordinate().equals(toCoordinate(artifact))) {
        throw new IOException("Maven " + viewName + " artifact coordinate changed after analysis");
      }
      if (!java.util.Objects.equals(snapshot.filePath(), normalizedPath(artifact))) {
        throw new IOException("Maven " + viewName + " artifact file path changed after analysis");
      }
    }
  }

  private static Path normalizedPath(final Artifact artifact) {
    final File file = artifact.getFile();
    return file == null ? null : file.toPath().toAbsolutePath().normalize();
  }

  private static boolean isJarCandidate(final ArtifactSnapshot snapshot) throws IOException {
    if (!"jar".equals(snapshot.coordinate().type())) {
      return false;
    }
    final Path file = snapshot.filePath();
    if (file == null) {
      throw new IOException("Resolved artifact has no regular file: " + snapshot.coordinate());
    }
    final Path fileName = file.getFileName();
    if (fileName == null || !Files.isRegularFile(file)) {
      throw new IOException("Resolved artifact has no regular file: " + snapshot.coordinate());
    }
    return fileName.toString().endsWith(".jar");
  }

  static boolean isJarCandidate(final Artifact artifact) throws IOException {
    return isJarCandidate(ArtifactSnapshot.from(artifact));
  }

  private static ArtifactCoordinate toCoordinate(final Artifact artifact) {
    return new ArtifactCoordinate(
        artifact.getGroupId(),
        artifact.getArtifactId(),
        artifact.getVersion(),
        artifact.getType(),
        artifact.getClassifier(),
        artifact.getScope());
  }

  private static PruneConfig config(
      final List<String> excludedArtifacts, final Set<ArtifactCoordinate> compileVisibleArtifacts)
      throws MojoFailureException {
    final Set<ArtifactCoordinate> exclusions = new LinkedHashSet<>();
    if (excludedArtifacts != null) {
      for (final String text : excludedArtifacts) {
        exclusions.add(parseExclusion(text));
      }
    }
    return new PruneConfig(Set.of(), compileVisibleArtifacts, ELIGIBLE_SCOPES, exclusions);
  }

  /** Resolves source roots or retains all compiler-visible classes. */
  private static CompilerInputs compilerInputs(
      final MavenProject project,
      final MavenSession session,
      final List<ArtifactFileRef> candidates,
      final ArtifactClassIndex index,
      final boolean sourceRootsComplete)
      throws IOException {
    final List<String> classpath;
    try {
      classpath = project.getCompileClasspathElements();
    } catch (final DependencyResolutionRequiredException exception) {
      throw new IOException(
          "Cannot resolve the Maven compile classpath for source analysis", exception);
    }
    final Set<Path> compileClasspath = normalizedPaths(classpath);
    final Set<ArtifactFileRef> compileVisibleArtifacts = new HashSet<>();
    for (final ArtifactFileRef candidate : candidates) {
      final String scope = candidate.coordinate().scope();
      if (COMPILE_VISIBLE_SCOPES.contains(scope)
          || compileClasspath.contains(candidate.filePath().toAbsolutePath().normalize())) {
        compileVisibleArtifacts.add(candidate);
      }
    }
    final Set<String> requiredClasses = new HashSet<>();
    final Map<ArtifactFileRef, Set<String>> indexedClasses = index.classesByArtifact();
    if (sourceRootsComplete) {
      final List<Path> sources =
          JavaSourceReferenceScanner.sourceFiles(project.getCompileSourceRoots());
      verifySourceRootsComplete(project, sources);
      if (sources.stream().anyMatch(MavenElisionService::isModuleDescriptor)) {
        throw new IOException("Source attribution does not support Java module descriptors");
      }
      final List<String> options = MavenCompilerSettings.options(project, session, classpath);
      requiredClasses.addAll(
          new JavaSourceReferenceScanner().scanFiles(sources, classpath, options));
      compileVisibleArtifacts.removeIf(
          artifact -> !sourceClassesByArtifact(artifact, requiredClasses, indexedClasses));
    } else {
      compileVisibleArtifacts.forEach(
          artifact -> requiredClasses.addAll(indexedClasses.getOrDefault(artifact, Set.of())));
    }
    final Set<ArtifactCoordinate> compileVisibleCoordinates = new HashSet<>();
    compileVisibleArtifacts.forEach(
        artifact -> compileVisibleCoordinates.add(artifact.coordinate()));
    return new CompilerInputs(compileVisibleCoordinates, requiredClasses);
  }

  private static boolean sourceClassesByArtifact(
      final ArtifactFileRef artifact,
      final Set<String> requiredClasses,
      final Map<ArtifactFileRef, Set<String>> indexedClasses) {
    return indexedClasses.getOrDefault(artifact, Set.of()).stream()
        .anyMatch(requiredClasses::contains);
  }

  private static boolean isModuleDescriptor(final Path source) {
    final Path fileName = source.getFileName();
    return fileName != null && "module-info.java".equals(fileName.toString());
  }

  private static void verifySourceRootsComplete(
      final MavenProject project, final List<Path> currentSources) throws IOException {
    if (currentSources.isEmpty()) {
      throw new IOException(
          "elide.sourceRootsComplete=true requires current production Java sources");
    }
    for (final String root : project.getCompileSourceRoots()) {
      if (!Files.isDirectory(Path.of(root))) {
        throw new IOException("A declared production source root is not present: " + root);
      }
    }
    if (hasUnknownSourceGeneration(project)) {
      throw new IOException(
          "elide.sourceRootsComplete=true conflicts with a source-generation lifecycle execution");
    }
  }

  private static boolean hasUnknownSourceGeneration(final MavenProject project) {
    final org.apache.maven.model.Build build = project.getBuild();
    if (build == null
        || !Set.of("jar", "pom", "war", "maven-plugin").contains(project.getPackaging())
        || !build.getExtensions().isEmpty()) {
      return true;
    }
    for (final Plugin plugin : build.getPlugins()) {
      for (final PluginExecution execution : plugin.getExecutions()) {
        if (!isKnownNonGeneratingExecution(plugin, execution)
            && (execution.getPhase() == null
                || phaseCanAddProductionSources(execution.getPhase()))) {
          return true;
        }
      }
    }
    return false;
  }

  private static boolean isKnownNonGeneratingExecution(
      final Plugin plugin, final PluginExecution execution) {
    if ("org.apache.maven.plugins".equals(plugin.getGroupId())
        && "maven-resources-plugin".equals(plugin.getArtifactId())) {
      return execution.getGoals().stream().allMatch("resources"::equals);
    }
    if ("org.apache.maven.plugins".equals(plugin.getGroupId())
        && "maven-compiler-plugin".equals(plugin.getArtifactId())) {
      return execution.getGoals().stream().allMatch(Set.of("compile", "testCompile")::contains);
    }
    return "io.github.spockz".equals(plugin.getGroupId())
        && "dependency-elider-maven-plugin".equals(plugin.getArtifactId())
        && execution.getGoals().stream().allMatch(Set.of("elide", "analyze")::contains);
  }

  private static boolean phaseCanAddProductionSources(final String phase) {
    return Set.of(
            "validate",
            "initialize",
            "generate-sources",
            "process-sources",
            "generate-resources",
            "process-resources",
            "compile")
        .contains(phase);
  }

  private static Set<Path> normalizedPaths(final List<String> classpath) throws IOException {
    final Set<Path> paths = new HashSet<>();
    for (final String entry : classpath) {
      try {
        paths.add(Path.of(entry).toAbsolutePath().normalize());
      } catch (final InvalidPathException exception) {
        throw new IOException("Invalid Maven compile classpath entry: " + entry, exception);
      }
    }
    return paths;
  }

  private record CompilerInputs(
      Set<ArtifactCoordinate> compileVisibleCoordinates, Set<String> requiredClasses) {
    private CompilerInputs {
      compileVisibleCoordinates = Set.copyOf(compileVisibleCoordinates);
      requiredClasses = Set.copyOf(requiredClasses);
    }
  }

  private static ArtifactCoordinate parseExclusion(final String text) throws MojoFailureException {
    final String[] pieces = text.split(":", -1);
    if (pieces.length < 2 || pieces.length > 5 || pieces[0].isBlank() || pieces[1].isBlank()) {
      throw new MojoFailureException(
          "Invalid elide.excludedArtifacts coordinate '"
              + text
              + "'; expected groupId:artifactId[:version[:type[:classifier]]]");
    }
    final String version = optionalPiece(pieces, 2, null);
    final String type = optionalPiece(pieces, 3, "jar");
    final String classifier = optionalPiece(pieces, 4, "");
    return new ArtifactCoordinate(pieces[0], pieces[1], version, type, classifier, "compile");
  }

  private static String optionalPiece(
      final String[] pieces, final int index, final String defaultValue) {
    return pieces.length > index && !pieces[index].isBlank() ? pieces[index] : defaultValue;
  }

  private static Collection<Path> toPaths(final List<File> files) {
    return files == null ? List.of() : files.stream().map(File::toPath).toList();
  }

  private static Set<ArtifactIdentity> identities(
      final Collection<ArtifactCoordinate> coordinates) {
    final Set<ArtifactIdentity> result = new LinkedHashSet<>();
    for (final ArtifactCoordinate coordinate : coordinates) {
      result.add(ArtifactIdentity.from(coordinate));
    }
    return result;
  }

  private static Set<Artifact> retained(
      final Collection<Artifact> input, final Set<ArtifactIdentity> elided) {
    final Set<Artifact> result = new LinkedHashSet<>();
    for (final Artifact artifact : input) {
      if (!elided.contains(ArtifactIdentity.from(toCoordinate(artifact)))) {
        result.add(artifact);
      }
    }
    return result;
  }

  @SuppressWarnings({"PMD.CyclomaticComplexity", "PMD.UseConcurrentHashMap"})
  private static void validateIdentityPaths(final List<ArtifactSnapshot> snapshots)
      throws IOException {
    final Map<ArtifactIdentity, Path> paths = new java.util.LinkedHashMap<>();
    for (final ArtifactSnapshot snapshot : snapshots) {
      if (!"jar".equals(snapshot.coordinate().type())) {
        continue;
      }
      final Path file = snapshot.filePath();
      if (file == null) {
        throw new IOException(
            "Resolved artifact has no regular JAR file: " + snapshot.coordinate());
      }
      final Path fileName = file.getFileName();
      if (fileName == null || !Files.isRegularFile(file) || !fileName.toString().endsWith(".jar")) {
        throw new IOException(
            "Resolved artifact has no regular JAR file: " + snapshot.coordinate());
      }
      final ArtifactIdentity identity = ArtifactIdentity.from(snapshot.coordinate());
      final Path previous = paths.putIfAbsent(identity, file);
      if (previous != null && !previous.equals(file)) {
        throw new IOException("Conflicting files for artifact identity " + identity);
      }
    }
  }

  @SuppressWarnings("PMD.UseConcurrentHashMap")
  private static void validateDirectPaths(
      final Collection<ArtifactSnapshot> resolved, final Collection<ArtifactSnapshot> direct)
      throws IOException {
    final Map<ArtifactIdentity, Path> resolvedPaths = new java.util.LinkedHashMap<>();
    for (final ArtifactSnapshot snapshot : resolved) {
      if ("jar".equals(snapshot.coordinate().type()) && snapshot.filePath() != null) {
        resolvedPaths.put(ArtifactIdentity.from(snapshot.coordinate()), snapshot.filePath());
      }
    }
    for (final ArtifactSnapshot snapshot : direct) {
      final ArtifactIdentity identity = ArtifactIdentity.from(snapshot.coordinate());
      final Path resolvedPath = resolvedPaths.get(identity);
      final Path file = snapshot.filePath();
      if (resolvedPath != null && file != null && !resolvedPath.equals(file)) {
        throw new IOException("Conflicting direct artifact file for identity " + identity);
      }
    }
  }

  record Analysis(
      List<ArtifactSnapshot> resolvedSnapshots,
      boolean directArtifactsPresent,
      List<ArtifactSnapshot> directSnapshots,
      ElisionDecision decision,
      ClassUsageReport classUsageReport,
      Optional<BytecodeReferenceScan> bytecodeScan) {
    Analysis(
        final List<ArtifactSnapshot> resolvedSnapshots,
        final boolean directArtifactsPresent,
        final List<ArtifactSnapshot> directSnapshots,
        final ElisionDecision decision) {
      this(
          resolvedSnapshots,
          directArtifactsPresent,
          directSnapshots,
          decision,
          new ClassUsageReport(List.of()),
          Optional.empty());
    }

    Analysis {
      resolvedSnapshots = List.copyOf(resolvedSnapshots);
      directSnapshots = List.copyOf(directSnapshots);
    }

    Set<Artifact> resolvedArtifacts() {
      return references(resolvedSnapshots);
    }

    Set<Artifact> directArtifacts() {
      return references(directSnapshots);
    }

    private static Set<Artifact> references(final List<ArtifactSnapshot> snapshots) {
      final Set<Artifact> result = new LinkedHashSet<>();
      snapshots.stream().map(ArtifactSnapshot::artifact).forEach(result::add);
      return Collections.unmodifiableSet(result);
    }
  }

  record ArtifactSnapshot(Artifact artifact, ArtifactCoordinate coordinate, Path filePath) {
    private static ArtifactSnapshot from(final Artifact artifact) {
      return new ArtifactSnapshot(artifact, toCoordinate(artifact), normalizedPath(artifact));
    }
  }

  record ApplyPlan(
      Set<Artifact> resolvedArtifacts,
      boolean directArtifactsPresent,
      Set<Artifact> directArtifacts) {
    ApplyPlan {
      resolvedArtifacts = Collections.unmodifiableSet(new LinkedHashSet<>(resolvedArtifacts));
      directArtifacts = Collections.unmodifiableSet(new LinkedHashSet<>(directArtifacts));
    }
  }

  private record ArtifactIdentity(
      String groupId, String artifactId, String version, String type, String classifier) {
    private static ArtifactIdentity from(final ArtifactCoordinate coordinate) {
      return new ArtifactIdentity(
          coordinate.groupId(),
          coordinate.artifactId(),
          coordinate.version(),
          coordinate.type(),
          coordinate.classifier());
    }
  }
}
