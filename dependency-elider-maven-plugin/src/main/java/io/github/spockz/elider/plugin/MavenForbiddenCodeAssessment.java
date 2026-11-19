// WHY: Applies explicit code policies to the production and effective artifact inventory of one
// goal.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.advisory.ForbiddenCodeInventory;
import io.github.spockz.elider.advisory.ForbiddenCodeInventory.Evidence;
import io.github.spockz.elider.advisory.ForbiddenRuntimeCalls;
import io.github.spockz.elider.advisory.ForbiddenSymbol;
import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.MavenVersionRangeMatcher;
import io.github.spockz.elider.model.VersionApplicability;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.AnalysisEvidence;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.ArtifactSnapshot;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.EffectiveAnalysis;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.PreparedAnalysis;
import io.github.spockz.elider.plugin.ForbiddenCodeAssessment.ComponentKind;
import io.github.spockz.elider.plugin.ForbiddenCodeAssessment.Match;
import io.github.spockz.elider.plugin.ForbiddenCodeAssessment.Mode;
import io.github.spockz.elider.plugin.ForbiddenCodeAssessment.Status;
import io.github.spockz.elider.plugin.ForbiddenCodeRule.MavenIdentity;
import io.github.spockz.elider.plugin.TrimGenerationPublisher.StagedArchive;
import io.github.spockz.elider.scanner.BytecodeReferenceScan;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import org.apache.maven.model.Build;
import org.apache.maven.plugin.logging.Log;
import org.apache.maven.project.MavenProject;

/** Adapts effective Maven providers to physical bytecode observations. */
@SuppressWarnings({
  "PMD.CommentRequired",
  "PMD.CommentDefaultAccessModifier",
  "PMD.TooManyMethods",
  "PMD.CouplingBetweenObjects",
  "PMD.GodClass",
  "PMD.ExcessiveImports",
  "PMD.AvoidInstantiatingObjectsInLoops",
  "PMD.UseConcurrentHashMap"
})
final class MavenForbiddenCodeAssessment {
  private static final String PHYSICAL_DECLARATIONS = "PHYSICAL_DECLARATIONS";
  private static final String STAGED = "STAGED_ARCHIVE_DECLARATIONS";
  private static final String CACHED = "CACHED_ARCHIVE_DECLARATIONS";
  private static final String EFFECTIVE_INVENTORY = "EFFECTIVE_COMPONENT_INVENTORY";
  private static final String NO_EVIDENCE = "INCOMPLETE_SCOPE";
  private static final String VERSION = "VERSION_SCOPE";
  private static final Pattern NUMERIC_RUNTIME_RANGE = Pattern.compile("[0-9.,()\\[\\]\\s]+");

  private final Mode mode;
  private final int targetRelease;
  private final boolean enforcementEnabled;

  private MavenForbiddenCodeAssessment(
      final Mode mode, final int targetRelease, final boolean enforce) {
    this.mode = mode;
    this.targetRelease = targetRelease;
    this.enforcementEnabled = enforce;
  }

  static List<ForbiddenCodeAssessment> predict(
      final MavenProject project,
      final AnalyzePrediction prediction,
      final ConfiguredVulnerabilityMappings configuration,
      final boolean enforce,
      final File productionOutput)
      throws IOException {
    if (configuration.forbiddenRules().isEmpty()) {
      return List.of();
    }
    final Map<ArtifactCoordinate, AnalyzePrediction.PlannedTrim> trims =
        prediction.plannedTrims().stream()
            .collect(
                Collectors.toUnmodifiableMap(
                    AnalyzePrediction.PlannedTrim::coordinate, Function.identity()));
    return new MavenForbiddenCodeAssessment(
            Mode.PREDICTED, prediction.executionEnvironment().targetRelease(), enforce)
        .assess(
            configuration.forbiddenRules(),
            new Inventory(
                project,
                ProductionEvidence.predicted(prediction.evidence(), productionOutput),
                prediction.inputArtifacts(),
                Set.copyOf(prediction.wouldElideArtifacts()),
                prediction.banPlan()),
            snapshot -> Provider.predicted(snapshot.filePath(), trims.get(snapshot.coordinate())));
  }

  static List<ForbiddenCodeAssessment> observe(
      final EffectiveAnalysis analysis,
      final ConfiguredVulnerabilityMappings configuration,
      final boolean enforce,
      final Map<ArtifactCoordinate, StagedArchive> archives)
      throws IOException {
    final PreparedAnalysis prepared = analysis.prepared();
    return new MavenForbiddenCodeAssessment(
            Mode.OBSERVED, analysis.trimAnalysis().targetRelease(), enforce)
        .assess(
            configuration.forbiddenRules(),
            new Inventory(
                prepared.project(),
                ProductionEvidence.observed(prepared),
                prepared.resolvedSnapshots(),
                analysis.effectiveDecision().elidedArtifacts(),
                analysis.banPlan()),
            snapshot -> Provider.observed(snapshot, archives.get(snapshot.coordinate())));
  }

  static void enforce(final List<ForbiddenCodeAssessment> results, final Log log)
      throws IOException {
    final List<ForbiddenCodeAssessment> violations =
        results.stream()
            .filter(row -> row.enforcementEnabled() && row.status() == Status.VIOLATION)
            .toList();
    if (violations.isEmpty()) {
      return;
    }
    violations.forEach(
        row ->
            log.error(
                "Forbidden code "
                    + row.mode()
                    + " VIOLATION: "
                    + row.cveId()
                    + " "
                    + row.symbol()
                    + " in "
                    + Objects.toString(
                        row.componentIdentity(), "target Java " + row.targetRelease())
                    + " ("
                    + Objects.toString(row.provider(), "runtime image unavailable")
                    + ", "
                    + row.evidenceKind()
                    + "). "
                    + row.reason()));
    throw new IOException("Forbidden code policy found " + violations.size() + " violation(s)");
  }

  private List<ForbiddenCodeAssessment> assess(
      final List<ForbiddenCodeRule> rules,
      final Inventory inventory,
      final ProviderLookup providers)
      throws IOException {
    final List<ForbiddenCodeAssessment> rows = new ArrayList<>();
    final Map<MavenIdentity, List<ForbiddenCodeRule>> artifactRules =
        rules.stream()
            .filter(rule -> rule.componentKind() == ComponentKind.MAVEN_ARTIFACT)
            .collect(Collectors.groupingBy(ForbiddenCodeRule::mavenIdentity));
    if (!artifactRules.isEmpty()) {
      assessArtifacts(inventory, providers, artifactRules, rows);
    }
    final List<ForbiddenCodeRule> projectRules =
        rules.stream()
            .filter(rule -> rule.componentKind() == ComponentKind.PROJECT_OUTPUT)
            .toList();
    if (!projectRules.isEmpty()) {
      assessProject(inventory, projectRules, rows);
    }
    assessRuntime(
        rules.stream().filter(rule -> rule.componentKind() == ComponentKind.JAVA_RUNTIME).toList(),
        inventory,
        providers,
        rows);
    return rows.stream()
        .sorted(
            Comparator.comparing(ForbiddenCodeAssessment::provenance)
                .thenComparing(ForbiddenCodeAssessment::symbol)
                .thenComparing(row -> Objects.toString(row.componentVersion(), ""))
                .thenComparing(row -> Objects.toString(row.provider(), "")))
        .toList();
  }

  @SuppressWarnings("PMD.CognitiveComplexity") // Keeps resolved and excluded candidates distinct.
  private void assessArtifacts(
      final Inventory inventory,
      final ProviderLookup providers,
      final Map<MavenIdentity, List<ForbiddenCodeRule>> artifactRules,
      final List<ForbiddenCodeAssessment> rows)
      throws IOException {
    final Map<MavenIdentity, List<ArtifactSnapshot>> candidates =
        inventory.artifacts().stream()
            .filter(snapshot -> !MavenArtifactInventory.isTestScoped(snapshot.coordinate()))
            .collect(Collectors.groupingBy(snapshot -> MavenIdentity.of(snapshot.coordinate())));
    final Map<MavenIdentity, List<ArtifactCoordinate>> excluded =
        inventory.banPlan().entries().stream()
            .flatMap(entry -> entry.originalArtifacts().stream())
            .filter(coordinate -> !MavenArtifactInventory.isTestScoped(coordinate))
            .distinct()
            .collect(Collectors.groupingBy(MavenIdentity::of));
    for (final Map.Entry<MavenIdentity, List<ForbiddenCodeRule>> entry : artifactRules.entrySet()) {
      final MavenIdentity identity = entry.getKey();
      final List<ForbiddenCodeRule> rules = entry.getValue();
      final List<ArtifactSnapshot> selected = candidates.getOrDefault(identity, List.of());
      final List<ArtifactCoordinate> original = excluded.getOrDefault(identity, List.of());
      for (final ArtifactSnapshot candidate : selected) {
        final ArtifactCoordinate coordinate = candidate.coordinate();
        final Component component = new Component(identity.display(), coordinate.version());
        if (inventory.dropped().contains(coordinate)) {
          rows.addAll(
              absent(rules, component, "Component is dropped from the effective inventory"));
        } else {
          final Provider provider = providers.find(candidate);
          rows.addAll(
              isClassProvider(coordinate, provider.inspectedPath())
                  ? physical(rules, component, provider, true)
                  : missing(
                      rules, component, "Effective artifact has no supported class provider"));
        }
      }
      for (final ArtifactCoordinate coordinate : original) {
        if (selected.stream().noneMatch(candidate -> candidate.coordinate().equals(coordinate))) {
          rows.addAll(
              absent(
                  rules,
                  new Component(identity.display(), coordinate.version()),
                  "Component is excluded from the effective inventory"));
        }
      }
      if (selected.isEmpty() && original.isEmpty()) {
        rules.stream()
            .map(
                rule ->
                    assessment(
                        rule,
                        new Component(identity.display(), null),
                        ForbiddenCodeAssessment.VersionApplicability.NO_COMPONENT,
                        Observation.of(
                            Status.PASS,
                            EFFECTIVE_INVENTORY,
                            true,
                            "No matching component in the effective non-test dependency"
                                + " inventory")))
            .forEach(rows::add);
      }
    }
  }

  private static boolean isClassProvider(final ArtifactCoordinate coordinate, final Path path) {
    return path != null
        && ("jar".equals(coordinate.type())
            || Files.isDirectory(path)
            || path.toString().endsWith(".jar"));
  }

  private void assessProject(
      final Inventory inventory,
      final List<ForbiddenCodeRule> rules,
      final List<ForbiddenCodeAssessment> rows)
      throws IOException {
    final MavenProject project = inventory.project();
    final ProductionEvidence evidence = inventory.production();
    final Component component =
        new Component(project.getGroupId() + ":" + project.getArtifactId(), project.getVersion());
    final Path primary = primaryOutput(inventory);
    final Path test = testOutput(project);
    final List<Path> roots = productionRoots(project, primary);
    if (roots.stream().anyMatch(root -> overlapsTest(root, test))) {
      rows.addAll(missing(rules, component, "Production output overlaps test class output"));
      return;
    }
    final boolean complete =
        primary != null
            && evidence.complete()
            && evidence.bytecodeScan().map(BytecodeReferenceScan::complete).orElse(false);
    if (roots.isEmpty()) {
      rows.addAll(missing(rules, component, "Production class output is unavailable"));
      return;
    }
    for (final Path root : roots) {
      if (Files.notExists(root)) {
        rows.addAll(
            complete
                ? absent(rules, component, "Complete production output has no classes at " + root)
                : missing(rules, component, "Production class output is unavailable at " + root));
      } else if (Files.isDirectory(root)) {
        rows.addAll(
            physical(
                rules,
                component,
                new Provider(root, root, Set.of(), null, PHYSICAL_DECLARATIONS),
                complete));
      } else {
        throw new IOException("Production class output is not a directory: " + root);
      }
    }
  }

  private static Path primaryOutput(final Inventory inventory) {
    final MavenProject project = inventory.project();
    final ProductionEvidence evidence = inventory.production();
    final String configured = productionPath(evidence.configured(), project.getBuild());
    return evidence
        .bytecodeScan()
        .map(BytecodeReferenceScan::scope)
        .orElseGet(() -> projectPath(project, configured));
  }

  private static Path testOutput(final MavenProject project) {
    final Build build = project.getBuild();
    return build == null ? null : projectPath(project, build.getTestOutputDirectory());
  }

  private static List<Path> productionRoots(final MavenProject project, final Path primary) {
    return java.util.stream.Stream.of(
            primary, SpringAotAssetPaths.resolveMainClasses(project).orElse(null))
        .filter(Objects::nonNull)
        .map(path -> path.toAbsolutePath().normalize())
        .distinct()
        .toList();
  }

  private static String productionPath(final File configured, final Build build) {
    if (configured != null) {
      return configured.getPath();
    }
    return build == null ? null : build.getOutputDirectory();
  }

  private static boolean overlapsTest(final Path root, final Path test) {
    return SpringAotAssetPaths.isTestAotPath(root)
        || (test != null && (root.startsWith(test) || test.startsWith(root)));
  }

  @SuppressWarnings("PMD.LawOfDemeter") // Maven resolves relative paths against the POM base.
  private static Path projectPath(final MavenProject project, final String configured) {
    if (configured == null || configured.isBlank()) {
      return null;
    }
    final Path path = Path.of(configured);
    final File base = project.getBasedir();
    return path.isAbsolute() || base == null
        ? path.toAbsolutePath().normalize()
        : base.toPath().resolve(path).toAbsolutePath().normalize();
  }

  private List<ForbiddenCodeAssessment> physical(
      final List<ForbiddenCodeRule> rules,
      final Component component,
      final Provider provider,
      final boolean complete)
      throws IOException {
    final Map<ForbiddenSymbol, ForbiddenCodeInventory.Result> results =
        ForbiddenCodeInventory.scan(
            provider.inspectedPath(),
            rules.stream()
                .filter(rule -> applicable(rule, component.version()))
                .map(ForbiddenCodeRule::symbol)
                .distinct()
                .toList(),
            provider.removedClasses(),
            provider.projectedEntries());
    final List<ForbiddenCodeAssessment> rows = new ArrayList<>();
    for (final ForbiddenCodeRule rule : rules) {
      if (!applicable(rule, component.version())) {
        rows.add(inapplicable(rule, component));
        continue;
      }
      final ForbiddenCodeInventory.Result result = results.get(rule.symbol());
      final Status status =
          switch (result.status()) {
            case VIOLATION -> Status.VIOLATION;
            case PASS -> complete ? Status.PASS : Status.UNKNOWN;
            case UNKNOWN -> Status.UNKNOWN;
          };
      final String path = provider.reportedPath().toString();
      final List<Match> matches =
          result.evidence().stream()
              .map(
                  match ->
                      new Match(
                          path,
                          match.entry(),
                          match.tier(),
                          match.owner(),
                          match.descriptor() == null ? List.of() : List.of(match.descriptor())))
              .toList();
      rows.add(
          assessment(
              rule,
              component,
              ForbiddenCodeAssessment.VersionApplicability.APPLICABLE,
              new Observation(
                  status,
                  provider.kind(),
                  path,
                  matches,
                  complete && result.complete(),
                  status == Status.UNKNOWN && !complete
                      ? "Production output is not known complete at the assessment boundary"
                      : result.reason())));
    }
    return rows;
  }

  private List<ForbiddenCodeAssessment> absent(
      final List<ForbiddenCodeRule> rules, final Component component, final String reason) {
    return rules.stream()
        .map(
            rule -> {
              return applicable(rule, component.version())
                  ? assessment(
                      rule,
                      component,
                      ForbiddenCodeAssessment.VersionApplicability.APPLICABLE,
                      Observation.of(Status.PASS, EFFECTIVE_INVENTORY, true, reason))
                  : inapplicable(rule, component);
            })
        .toList();
  }

  private List<ForbiddenCodeAssessment> missing(
      final List<ForbiddenCodeRule> rules, final Component component, final String reason) {
    return rules.stream()
        .map(
            rule ->
                applicable(rule, component.version())
                    ? assessment(
                        rule,
                        component,
                        ForbiddenCodeAssessment.VersionApplicability.APPLICABLE,
                        Observation.of(Status.UNKNOWN, NO_EVIDENCE, false, reason))
                    : inapplicable(rule, component))
        .toList();
  }

  private void assessRuntime(
      final List<ForbiddenCodeRule> rules,
      final Inventory inventory,
      final ProviderLookup providers,
      final List<ForbiddenCodeAssessment> rows)
      throws IOException {
    final Map<ForbiddenCodeRule, ForbiddenCodeAssessment> scoped = new java.util.LinkedHashMap<>();
    for (final ForbiddenCodeRule rule : rules) {
      scoped.put(rule, runtimeScope(rule));
    }
    final List<ForbiddenSymbol> symbols =
        scoped.entrySet().stream()
            .filter(
                entry ->
                    entry.getValue().versionApplicability()
                        != ForbiddenCodeAssessment.VersionApplicability.NOT_APPLICABLE)
            .map(entry -> entry.getKey().symbol())
            .filter(symbol -> symbol.method() != null)
            .distinct()
            .toList();
    final Map<ForbiddenSymbol, List<RuntimeCallHit>> matches =
        symbols.isEmpty() ? Map.of() : runtimeMatches(inventory, providers, symbols);
    scoped.forEach((rule, row) -> rows.add(runtimeResult(rule, row, matches.get(rule.symbol()))));
  }

  private ForbiddenCodeAssessment runtimeResult(
      final ForbiddenCodeRule rule,
      final ForbiddenCodeAssessment row,
      final List<RuntimeCallHit> hits) {
    if (hits == null
        || row.versionApplicability()
            == ForbiddenCodeAssessment.VersionApplicability.NOT_APPLICABLE) {
      return row;
    }
    final Component component = new Component(row.componentIdentity(), row.componentVersion());
    if (!ForbiddenRuntimeCalls.unambiguous(hits.stream().map(RuntimeCallHit::evidence).toList())) {
      return assessment(
          rule,
          component,
          row.versionApplicability(),
          new Observation(
              Status.UNKNOWN,
              row.evidenceKind(),
              row.provider(),
              List.of(),
              false,
              "Direct invocations match multiple symbolic target identities. " + row.reason()));
    }
    final List<Match> callSites =
        hits.stream()
            .map(RuntimeCallHit::reportMatch)
            .distinct()
            .sorted(
                Comparator.comparing(Match::provider)
                    .thenComparing(Match::entry)
                    .thenComparing(match -> match.descriptors().getFirst()))
            .toList();
    final Match first = callSites.getFirst();
    final String reason =
        "Exact invocation found in effective bytecode at " + first.provider() + "!" + first.entry();
    return assessment(
        rule,
        component,
        row.versionApplicability(),
        new Observation(
            Status.VIOLATION,
            ForbiddenCodeAssessment.DIRECT_RUNTIME_CALL,
            row.provider(),
            callSites,
            false,
            row.versionApplicability() == ForbiddenCodeAssessment.VersionApplicability.UNKNOWN
                ? reason + ". " + row.reason()
                : reason));
  }

  private Map<ForbiddenSymbol, List<RuntimeCallHit>> runtimeMatches(
      final Inventory inventory,
      final ProviderLookup providers,
      final List<ForbiddenSymbol> symbols)
      throws IOException {
    final ForbiddenRuntimeCalls calls = ForbiddenRuntimeCalls.index(symbols);
    final Map<ForbiddenSymbol, List<RuntimeCallHit>> matches = new HashMap<>();
    final Path test = testOutput(inventory.project());
    for (final Path root : productionRoots(inventory.project(), primaryOutput(inventory))) {
      if (!overlapsTest(root, test) && Files.isDirectory(root)) {
        scanCalls(calls, new Provider(root, root, Set.of(), null, PHYSICAL_DECLARATIONS), matches);
      }
    }
    for (final ArtifactSnapshot artifact : inventory.artifacts()) {
      if (!MavenArtifactInventory.isTestScoped(artifact.coordinate())
          && !inventory.dropped().contains(artifact.coordinate())) {
        final Provider provider = providers.find(artifact);
        if (isClassProvider(artifact.coordinate(), provider.inspectedPath())) {
          scanCalls(calls, provider, matches);
        }
      }
    }
    return matches;
  }

  private void scanCalls(
      final ForbiddenRuntimeCalls calls,
      final Provider provider,
      final Map<ForbiddenSymbol, List<RuntimeCallHit>> matches)
      throws IOException {
    calls
        .scan(
            provider.inspectedPath(),
            provider.removedClasses(),
            provider.projectedEntries(),
            targetRelease)
        .forEach(
            (symbol, evidence) ->
                matches
                    .computeIfAbsent(symbol, ignored -> new ArrayList<>())
                    .addAll(
                        evidence.stream()
                            .map(hit -> new RuntimeCallHit(provider.reportedPath().toString(), hit))
                            .toList()));
  }

  private ForbiddenCodeAssessment runtimeScope(final ForbiddenCodeRule rule) {
    final Runtime.Version active = Runtime.version();
    if (targetRelease != active.feature()) {
      return assessment(
          rule,
          new Component(null, null),
          ForbiddenCodeAssessment.VersionApplicability.UNKNOWN,
          Observation.of(
              Status.UNKNOWN,
              NO_EVIDENCE,
              false,
              "No inspected Java runtime image for target release " + targetRelease));
    }
    final Component component =
        new Component(System.getProperty("java.runtime.name"), active.toString());
    final String range = rule.version().normalizedMavenRange();
    final String numericVersion =
        active.version().stream().map(String::valueOf).collect(Collectors.joining("."));
    final String image = System.getProperty("java.home");
    final boolean supported =
        "(,)".equals(range)
            || (active.pre().isEmpty() && NUMERIC_RUNTIME_RANGE.matcher(range).matches());
    if (!supported) {
      return assessment(
          rule,
          component,
          ForbiddenCodeAssessment.VersionApplicability.UNKNOWN,
          new Observation(
              Status.UNKNOWN,
              VERSION,
              image,
              List.of(),
              false,
              "Runtime version scope cannot be evaluated against this runtime identity"));
    }
    if (!MavenVersionRangeMatcher.includes(range, numericVersion)) {
      return inapplicable(rule, component);
    }
    return assessment(
        rule,
        component,
        ForbiddenCodeAssessment.VersionApplicability.APPLICABLE,
        new Observation(
            Status.UNKNOWN,
            "RUNTIME_REACHABILITY",
            image,
            List.of(),
            false,
            "Available runtime evidence does not establish method or class reachability"));
  }

  private static boolean applicable(final ForbiddenCodeRule rule, final String version) {
    return version != null
        && !version.isBlank()
        && MavenVersionRangeMatcher.includes(rule.version().normalizedMavenRange(), version);
  }

  private ForbiddenCodeAssessment inapplicable(
      final ForbiddenCodeRule rule, final Component component) {
    if (component.version() == null || component.version().isBlank()) {
      return assessment(
          rule,
          component,
          ForbiddenCodeAssessment.VersionApplicability.UNKNOWN,
          Observation.of(Status.UNKNOWN, VERSION, false, "Concrete component version unavailable"));
    }
    return assessment(
        rule,
        component,
        ForbiddenCodeAssessment.VersionApplicability.NOT_APPLICABLE,
        Observation.of(
            Status.NOT_APPLICABLE,
            VERSION,
            true,
            "Concrete component version is outside the configured scope"));
  }

  private ForbiddenCodeAssessment assessment(
      final ForbiddenCodeRule rule,
      final Component component,
      final ForbiddenCodeAssessment.VersionApplicability applicability,
      final Observation observation) {
    return new ForbiddenCodeAssessment(
        rule.cveId(),
        rule.symbol().value(),
        rule.componentKind(),
        component.identity(),
        rule.version().normalizedMavenRange(),
        component.version(),
        targetRelease,
        rule.version().status() == VersionApplicability.AFFECTED,
        applicability,
        mode,
        observation.status(),
        observation.kind(),
        observation.provider(),
        observation.matches(),
        observation.complete(),
        observation.reason(),
        rule.provenance().sourceRecordId(),
        Objects.toString(rule.provenance().sourceUrl(), null),
        enforcementEnabled);
  }

  private record Inventory(
      MavenProject project,
      ProductionEvidence production,
      List<ArtifactSnapshot> artifacts,
      Set<ArtifactCoordinate> dropped,
      MavenBanPlan banPlan) {}

  private record ProductionEvidence(
      Optional<BytecodeReferenceScan> bytecodeScan, File configured, boolean complete) {
    static ProductionEvidence predicted(final AnalysisEvidence evidence, final File configured) {
      return new ProductionEvidence(
          evidence.bytecodeScan(),
          configured,
          evidence.productionClassesComplete() || evidence.trustedProcessClassesContext());
    }

    static ProductionEvidence observed(final PreparedAnalysis prepared) {
      final ElisionAnalysisModel.AnalysisOptions options = prepared.options();
      final ElisionAnalysisModel.CompletenessOptions completeness = options.completeness();
      return new ProductionEvidence(
          prepared.bytecodeScan(),
          options.productionOutput(),
          completeness.productionClassesComplete() || completeness.trustedProcessClassesContext());
    }
  }

  private record Component(String identity, String version) {}

  private record RuntimeCallHit(String provider, Evidence evidence) {
    private Match reportMatch() {
      return new Match(
          provider,
          evidence.entry(),
          evidence.tier(),
          evidence.owner(),
          List.of(evidence.descriptor()));
    }
  }

  @FunctionalInterface
  private interface ProviderLookup {
    Provider find(ArtifactSnapshot snapshot) throws IOException;
  }

  private record Observation(
      Status status,
      String kind,
      String provider,
      List<Match> matches,
      boolean complete,
      String reason) {
    static Observation of(
        final Status status, final String kind, final boolean complete, final String reason) {
      return new Observation(status, kind, null, List.of(), complete, reason);
    }
  }

  private record Provider(
      Path inspectedPath,
      Path reportedPath,
      Set<String> removedClasses,
      Map<String, String> projectedEntries,
      String kind) {
    static Provider predicted(final Path jar, final AnalyzePrediction.PlannedTrim trim)
        throws IOException {
      final AnalyzePrediction.PhysicalProjection projection =
          trim == null ? null : trim.physicalProjection();
      return new Provider(
          jar,
          jar,
          trim == null ? Set.of() : trim.removedClasses(),
          projection == null ? null : projection.classEntries(),
          PHYSICAL_DECLARATIONS);
    }

    static Provider observed(final ArtifactSnapshot original, final StagedArchive archive) {
      return archive == null
          ? new Provider(
              original.filePath(), original.filePath(), Set.of(), null, PHYSICAL_DECLARATIONS)
          : new Provider(
              archive.inspectedPath(),
              archive.outputPath(),
              Set.of(),
              null,
              archive.inspectedPath().equals(archive.outputPath()) ? CACHED : STAGED);
    }
  }
}
