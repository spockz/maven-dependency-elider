// WHY: Binds an isolated Maven resolver graph to exact direct and resolved artifact views.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.ArtifactSnapshot;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.ArtifactViews;
import java.io.IOException;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.project.DefaultDependencyResolutionRequest;
import org.apache.maven.project.DependencyResolutionException;
import org.apache.maven.project.DependencyResolutionResult;
import org.apache.maven.project.MavenProject;
import org.apache.maven.project.ProjectDependenciesResolver;
import org.eclipse.aether.RepositorySystemSession;
import org.eclipse.aether.graph.Dependency;
import org.eclipse.aether.graph.DependencyNode;

/** Holds a validated graph pair and its exact Maven artifact views. */
record MavenAnalysisResolutionContext(
    MavenProject project,
    MavenProject liveProject,
    Provenance provenance,
    AnalysisEnvironment environment,
    ArtifactViews artifacts,
    String resolvedFingerprint,
    String directFingerprint,
    ResolverArtifactGraphCapturePair pair) {
  /** Identifies which Maven inventory the isolated Resolver context represents. */
  /* package */ enum Provenance {
    CAPTURED_EFFECTIVE_RESOLVER,
    DETACHED_CURRENT_MODEL
  }

  MavenAnalysisResolutionContext {
    Objects.requireNonNull(project, "project");
    Objects.requireNonNull(liveProject, "liveProject");
    Objects.requireNonNull(provenance, "provenance");
    Objects.requireNonNull(environment, "environment");
    Objects.requireNonNull(artifacts, "artifacts");
    Objects.requireNonNull(resolvedFingerprint, "resolvedFingerprint");
    Objects.requireNonNull(directFingerprint, "directFingerprint");
    Objects.requireNonNull(pair, "pair");
    if (sameInstance(project, liveProject)) {
      throw new IllegalArgumentException("Maven resolution context must own a project clone");
    }
    if (!MavenElisionGraphInventory.matchesGraph(pair.after(), artifacts.resolvedSnapshots())) {
      throw new IllegalArgumentException("Maven graph pair does not match its resolved inventory");
    }
  }

  /* default */ static MavenAnalysisResolutionContext capturedEffective(
      final MavenProject project,
      final MavenProject liveProject,
      final MavenSession session,
      final AnalysisEnvironment environment)
      throws IOException {
    final List<ArtifactSnapshot> resolved =
        MavenArtifactInventory.snapshots(new ArrayList<>(project.getArtifacts()));
    final Set<Artifact> directArtifacts = project.getDependencyArtifacts();
    final boolean directPresent = directArtifacts != null;
    final List<ArtifactSnapshot> direct =
        MavenArtifactInventory.snapshots(
            directPresent ? new ArrayList<>(directArtifacts) : List.of());
    final ResolverArtifactGraphCapturePair pair =
        MavenElisionGraphBinding.requireCapturedPair(project, session, resolved);
    if (directPresent && !MavenElisionGraphInventory.matchesDirectGraph(pair.after(), direct)) {
      throw new IOException("Captured Maven graph does not match its direct inventory");
    }
    return create(
        project,
        liveProject,
        Provenance.CAPTURED_EFFECTIVE_RESOLVER,
        environment,
        resolved,
        directPresent,
        direct,
        pair);
  }

  /* default */ static MavenProject currentModel(final MavenProject project) {
    return new MavenProject(project);
  }

  /* default */ static MavenAnalysisResolutionContext forOperation(
      final MavenProject project,
      final MavenProject liveProject,
      final MavenSession session,
      final ProjectDependenciesResolver resolver,
      final AnalysisEnvironment environment)
      throws IOException {
    final boolean hookPresent =
        session != null
            && Boolean.TRUE.equals(
                EliderPreparationState.sessionData(session)
                    .get(MavenOriginalInputAudit.HOOK_PRESENT_KEY));
    return hookPresent
        ? capturedEffective(project, liveProject, session, environment)
        : detachedCurrentModel(project, liveProject, session, resolver, environment);
  }

  /* default */ static MavenAnalysisResolutionContext detachedCurrentModel(
      final MavenProject project,
      final MavenProject liveProject,
      final MavenSession session,
      final ProjectDependenciesResolver resolver,
      final AnalysisEnvironment environment)
      throws IOException {
    if (resolver == null) {
      throw new IOException("Detached Maven resolution requires a ProjectDependenciesResolver");
    }
    final RepositorySystemSession baseSession = repositorySession(session);
    if (baseSession == null) {
      throw new IOException("Detached Maven resolution requires a Resolver session");
    }
    final MavenProject detachedProject = detachedProject(project);
    final String projectKey = MavenElisionGraphBinding.projectKey(project);
    final RequestLocalResolverGraphCapture.Request request =
        RequestLocalResolverGraphCapture.create(baseSession, projectKey);
    final MavenOriginalInputResolution.Validated validated =
        resolveDetachedModel(projectKey, detachedProject, resolver, request);
    final DetachedInventories inventories = inventories(validated);
    MavenArtifactPathValidation.validateIdentityPaths(inventories.resolved());
    MavenArtifactPathValidation.validateIdentityPaths(inventories.direct());
    detachedProject.setResolvedArtifacts(mavenArtifactsFromDependencies(validated.dependencies()));
    detachedProject.setArtifacts(mavenArtifactsFromDependencies(validated.dependencies()));
    detachedProject.setDependencyArtifacts(
        mavenArtifactsFromNodes(validated.graph().getChildren()));
    return create(
        detachedProject,
        liveProject,
        Provenance.DETACHED_CURRENT_MODEL,
        environment,
        inventories.resolved(),
        true,
        inventories.direct(),
        inventories.pair());
  }

  @SuppressWarnings(
      "PMD.LawOfDemeter") // MavenSession exposes the Resolver session at this boundary.
  private static RepositorySystemSession repositorySession(final MavenSession session) {
    return session == null ? null : session.getRepositorySession();
  }

  private static MavenProject detachedProject(final MavenProject project) {
    final MavenProject detachedProject = new MavenProject(project);
    detachedProject.setDependencyArtifacts(null);
    detachedProject.setResolvedArtifacts(Set.of());
    detachedProject.setArtifactFilter(null);
    detachedProject.setManagedVersionMap(null);
    return detachedProject;
  }

  @SuppressWarnings("PMD.AvoidCatchingGenericException")
  // Resolver runtime failures must stop prediction at this external boundary.
  private static MavenOriginalInputResolution.Validated resolveDetachedModel(
      final String projectKey,
      final MavenProject detachedProject,
      final ProjectDependenciesResolver resolver,
      final RequestLocalResolverGraphCapture.Request request)
      throws IOException {
    final DependencyResolutionResult result;
    try {
      result =
          resolver.resolve(
              new DefaultDependencyResolutionRequest(detachedProject, request.session()));
    } catch (final DependencyResolutionException exception) {
      throw new IOException("Cannot resolve the detached current Maven model", exception);
    } catch (final RuntimeException exception) {
      throw new IOException(
          "Resolver failed while resolving the detached current Maven model", exception);
    }
    return MavenOriginalInputResolution.validate(projectKey, result, request.graphCapture().pair());
  }

  private static DetachedInventories inventories(
      final MavenOriginalInputResolution.Validated validated) throws IOException {
    final List<ArtifactSnapshot> resolved = snapshotsFromDependencies(validated.dependencies());
    final List<ArtifactSnapshot> direct = snapshotsFromNodes(validated.graph().getChildren());
    final ResolverArtifactGraphCapturePair pair = validated.graphPair();
    if (!MavenElisionGraphInventory.matchesGraph(pair.after(), resolved)) {
      throw new IOException("Detached Maven graph does not match its resolver inventory");
    }
    if (!direct.stream()
            .map(ArtifactSnapshot::coordinate)
            .sorted()
            .toList()
            .equals(MavenOriginalInputArtifacts.direct(validated.graph()))
        || !MavenElisionGraphInventory.matchesDirectGraph(pair.after(), direct)) {
      throw new IOException("Detached Maven direct inventory does not match its graph");
    }
    return new DetachedInventories(resolved, direct, pair);
  }

  /* default */ void verify() throws IOException {
    MavenElisionGraphBinding.verifyInventoryFingerprint(
        artifacts.resolvedSnapshots(), resolvedFingerprint);
    if (artifacts.directArtifactsPresent()) {
      MavenElisionGraphBinding.verifyInventoryFingerprint(
          artifacts.directSnapshots(), directFingerprint);
    }
    for (final ArtifactSnapshot snapshot : artifacts.resolvedSnapshots()) {
      if ("jar".equals(snapshot.coordinate().type())
          && (snapshot.filePath() == null
              || !Files.isRegularFile(snapshot.filePath())
              || !Files.isReadable(snapshot.filePath()))) {
        throw new IOException("Maven provider is no longer readable: " + snapshot.coordinate());
      }
    }
  }

  /* default */ String graphPairFingerprint() {
    return graphPairFingerprint(pair);
  }

  /* default */ static String graphPairFingerprint(final ResolverArtifactGraphCapturePair pair) {
    return MavenElisionGraphBinding.sha256(
        List.of(
            "request-local-graph-pair-v1",
            pair.before().graphFingerprint(),
            pair.after().graphFingerprint()));
  }

  private static MavenAnalysisResolutionContext create(
      final MavenProject project,
      final MavenProject liveProject,
      final Provenance provenance,
      final AnalysisEnvironment environment,
      final List<ArtifactSnapshot> resolved,
      final boolean directPresent,
      final List<ArtifactSnapshot> direct,
      final ResolverArtifactGraphCapturePair pair)
      throws IOException {
    MavenArtifactPathValidation.validateIdentityPaths(resolved);
    MavenArtifactPathValidation.validateIdentityPaths(direct);
    final ArtifactViews views = new ArtifactViews(resolved, directPresent, direct);
    return new MavenAnalysisResolutionContext(
        project,
        liveProject,
        provenance,
        environment,
        views,
        ResolvedArtifactInventoryFingerprint.fingerprint(resolved),
        directPresent ? ResolvedArtifactInventoryFingerprint.fingerprint(direct) : "missing",
        pair);
  }

  private static List<ArtifactSnapshot> snapshotsFromDependencies(
      final List<Dependency> dependencies) throws IOException {
    final List<ArtifactSnapshot> snapshots = new ArrayList<>(dependencies.size());
    for (final Dependency dependency : dependencies) {
      snapshots.add(snapshot(dependency));
    }
    snapshots.sort(Comparator.comparing(ArtifactSnapshot::coordinate));
    return List.copyOf(snapshots);
  }

  private static List<ArtifactSnapshot> snapshotsFromNodes(final List<DependencyNode> nodes)
      throws IOException {
    final List<ArtifactSnapshot> snapshots = new ArrayList<>(nodes.size());
    for (final DependencyNode node : nodes) {
      final Dependency dependency = dependency(node);
      if (dependency != null) {
        snapshots.add(snapshot(dependency));
      }
    }
    snapshots.sort(Comparator.comparing(ArtifactSnapshot::coordinate));
    return List.copyOf(snapshots);
  }

  private static Set<Artifact> mavenArtifactsFromDependencies(final List<Dependency> dependencies) {
    final Set<Artifact> artifacts = new java.util.LinkedHashSet<>();
    for (final Dependency dependency : dependencies) {
      if (dependency == null || dependency.getArtifact() == null) {
        throw new IllegalArgumentException("Detached Maven resolver returned a null dependency");
      }
      final Artifact artifact =
          org.apache.maven.RepositoryUtils.toArtifact(dependency.getArtifact());
      artifact.setScope(dependency.getScope());
      artifacts.add(artifact);
    }
    return artifacts;
  }

  private static Set<Artifact> mavenArtifactsFromNodes(final List<DependencyNode> nodes) {
    final Set<Artifact> artifacts = new java.util.LinkedHashSet<>();
    for (final DependencyNode node : nodes) {
      if (node == null) {
        throw new IllegalArgumentException(
            "Detached Maven resolver returned a null direct dependency");
      }
      final Dependency dependency = dependency(node);
      if (dependency == null || dependency.getArtifact() == null) {
        throw new IllegalArgumentException(
            "Detached Maven resolver returned a null direct dependency");
      }
      final Artifact artifact =
          org.apache.maven.RepositoryUtils.toArtifact(dependency.getArtifact());
      artifact.setScope(dependency.getScope());
      artifacts.add(artifact);
    }
    return artifacts;
  }

  private static Dependency dependency(final DependencyNode node) {
    return node.getDependency();
  }

  @SuppressWarnings("PMD.CompareObjectsWithEquals")
  // WHY: Identity distinguishes the live project from its clone.
  private static boolean sameInstance(final Object left, final Object right) {
    return left == right;
  }

  private static ArtifactSnapshot snapshot(final Dependency dependency) throws IOException {
    if (dependency == null || dependency.getArtifact() == null) {
      throw new IllegalArgumentException("Detached Maven resolver returned a null dependency");
    }
    return snapshot(dependency.getArtifact(), dependency.getScope());
  }

  private static ArtifactSnapshot snapshot(
      final org.eclipse.aether.artifact.Artifact artifact, final String scope) throws IOException {
    final ArtifactCoordinate coordinate = MavenOriginalInputArtifacts.coordinate(artifact, scope);
    MavenOriginalInputArtifacts.mavenType(artifact, coordinate);
    final Artifact mavenArtifact = org.apache.maven.RepositoryUtils.toArtifact(artifact);
    mavenArtifact.setScope(scope);
    return ArtifactSnapshot.from(mavenArtifact);
  }

  private record DetachedInventories(
      List<ArtifactSnapshot> resolved,
      List<ArtifactSnapshot> direct,
      ResolverArtifactGraphCapturePair pair) {}
}
