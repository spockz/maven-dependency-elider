// WHY: Keeps one Analyze resolver graph and its direct/resolved artifact views bound together.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.plugin.AnalyzePrediction.Provenance;
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
@SuppressWarnings("PMD.CouplingBetweenObjects")
record MavenAnalysisResolutionContext(
    MavenProject project,
    MavenProject liveProject,
    Provenance provenance,
    AnalysisEnvironment environment,
    ArtifactViews artifacts,
    String resolvedFingerprint,
    String directFingerprint,
    ResolverArtifactGraphCapturePair pair) {
  MavenAnalysisResolutionContext {
    Objects.requireNonNull(project, "project");
    Objects.requireNonNull(liveProject, "liveProject");
    Objects.requireNonNull(provenance, "provenance");
    Objects.requireNonNull(environment, "environment");
    Objects.requireNonNull(artifacts, "artifacts");
    Objects.requireNonNull(resolvedFingerprint, "resolvedFingerprint");
    Objects.requireNonNull(directFingerprint, "directFingerprint");
    Objects.requireNonNull(pair, "pair");
    if (project == liveProject) {
      throw new IllegalArgumentException("Analyze resolution context must own a project clone");
    }
    if (!MavenElisionGraphInventory.matchesGraph(pair.after(), artifacts.resolvedSnapshots())) {
      throw new IllegalArgumentException(
          "Analyze graph pair does not match its resolved inventory");
    }
  }

  static MavenAnalysisResolutionContext capturedEffective(
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
      throw new IOException("Captured Analyze graph does not match its direct inventory");
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

  static MavenProject currentModel(final MavenProject project) {
    return new MavenProject(project);
  }

  static MavenAnalysisResolutionContext forAnalyze(
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

  static MavenAnalysisResolutionContext detachedCurrentModel(
      final MavenProject project,
      final MavenProject liveProject,
      final MavenSession session,
      final ProjectDependenciesResolver resolver,
      final AnalysisEnvironment environment)
      throws IOException {
    Objects.requireNonNull(resolver, "resolver");
    final RepositorySystemSession baseSession =
        session == null ? null : session.getRepositorySession();
    if (baseSession == null) {
      throw new IOException("Detached Analyze resolution requires a Maven Resolver session");
    }
    final MavenProject detachedProject = new MavenProject(project);
    detachedProject.setDependencyArtifacts(null);
    detachedProject.setResolvedArtifacts(Set.of());
    detachedProject.setArtifactFilter(null);
    detachedProject.setManagedVersionMap(null);
    final String projectKey = MavenElisionGraphBinding.projectKey(project);
    final RequestLocalResolverGraphCapture.Request request =
        RequestLocalResolverGraphCapture.create(baseSession, projectKey);
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
    final MavenOriginalInputResolution.Validated validated =
        MavenOriginalInputResolution.validate(projectKey, result, request.graphCapture().pair());
    final List<ArtifactSnapshot> resolved = snapshotsFromDependencies(validated.dependencies());
    final List<ArtifactSnapshot> direct = snapshotsFromNodes(validated.graph().getChildren());
    final ResolverArtifactGraphCapturePair pair = validated.graphPair();
    if (!MavenElisionGraphInventory.matchesGraph(pair.after(), resolved)) {
      throw new IOException("Detached Analyze graph does not match its resolver inventory");
    }
    if (!direct.stream()
            .map(ArtifactSnapshot::coordinate)
            .sorted()
            .toList()
            .equals(MavenOriginalInputArtifacts.direct(validated.graph()))
        || !MavenElisionGraphInventory.matchesDirectGraph(pair.after(), direct)) {
      throw new IOException("Detached Analyze direct inventory does not match its graph");
    }
    MavenArtifactPathValidation.validateIdentityPaths(resolved);
    MavenArtifactPathValidation.validateIdentityPaths(direct);
    detachedProject.setResolvedArtifacts(mavenArtifactsFromDependencies(validated.dependencies()));
    detachedProject.setArtifacts(mavenArtifactsFromDependencies(validated.dependencies()));
    detachedProject.setDependencyArtifacts(
        mavenArtifactsFromNodes(validated.graph().getChildren()));
    return create(
        detachedProject,
        liveProject,
        Provenance.DETACHED_CURRENT_MODEL,
        environment,
        resolved,
        true,
        direct,
        pair);
  }

  void verify() throws IOException {
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
        throw new IOException("Analyze provider is no longer readable: " + snapshot.coordinate());
      }
    }
  }

  String graphPairFingerprint() {
    return graphPairFingerprint(pair);
  }

  static String graphPairFingerprint(final ResolverArtifactGraphCapturePair pair) {
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
      final List<Dependency> dependencies) {
    return dependencies.stream()
        .map(MavenAnalysisResolutionContext::snapshot)
        .sorted(Comparator.comparing(ArtifactSnapshot::coordinate))
        .toList();
  }

  private static List<ArtifactSnapshot> snapshotsFromNodes(final List<DependencyNode> nodes) {
    return nodes.stream()
        .map(DependencyNode::getDependency)
        .filter(Objects::nonNull)
        .map(MavenAnalysisResolutionContext::snapshot)
        .sorted(Comparator.comparing(ArtifactSnapshot::coordinate))
        .toList();
  }

  private static Set<Artifact> mavenArtifactsFromDependencies(final List<Dependency> dependencies) {
    final Set<Artifact> artifacts = new java.util.LinkedHashSet<>();
    for (final Dependency dependency : dependencies) {
      if (dependency == null || dependency.getArtifact() == null) {
        throw new IllegalArgumentException("Detached Analyze resolver returned a null dependency");
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
      if (node == null
          || node.getDependency() == null
          || node.getDependency().getArtifact() == null) {
        throw new IllegalArgumentException(
            "Detached Analyze resolver returned a null direct dependency");
      }
      final Dependency dependency = node.getDependency();
      final Artifact artifact =
          org.apache.maven.RepositoryUtils.toArtifact(dependency.getArtifact());
      artifact.setScope(dependency.getScope());
      artifacts.add(artifact);
    }
    return artifacts;
  }

  private static ArtifactSnapshot snapshot(final Dependency dependency) {
    if (dependency == null || dependency.getArtifact() == null) {
      throw new IllegalArgumentException("Detached Analyze resolver returned a null dependency");
    }
    return snapshot(dependency.getArtifact(), dependency.getScope());
  }

  private static ArtifactSnapshot snapshot(
      final org.eclipse.aether.artifact.Artifact artifact, final String scope) {
    final Artifact mavenArtifact = org.apache.maven.RepositoryUtils.toArtifact(artifact);
    mavenArtifact.setScope(scope);
    return ArtifactSnapshot.from(mavenArtifact);
  }
}
