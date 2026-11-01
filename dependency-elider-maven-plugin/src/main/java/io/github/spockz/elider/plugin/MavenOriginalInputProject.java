// WHY: Rebuilds a detached Maven project from the pre-injection model snapshot.

package io.github.spockz.elider.plugin;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import org.apache.maven.model.Dependency;
import org.apache.maven.model.DependencyManagement;
import org.apache.maven.model.Exclusion;
import org.apache.maven.project.MavenProject;

/** Creates request-local Maven model state for the original-input audit. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class MavenOriginalInputProject {
  private MavenOriginalInputProject() {}

  /** Rebuilds dependencies and management, then clears derived project caches. */
  static MavenProject reconstruct(
      final MavenProject liveProject, final BanishedDependencyOriginalModel captured)
      throws IOException {
    final MavenProject auditProject = new MavenProject(liveProject);
    auditProject.setDependencies(toDependencies(captured.effectiveDependencies()));
    if (auditProject.getModel() == null) {
      throw new IOException("Cannot reconstruct the original dependency-management model");
    }
    auditProject.getModel().setDependencyManagement(toManagement(captured.effectiveManagement()));
    auditProject.setDependencyArtifacts(null);
    auditProject.setResolvedArtifacts(Set.of());
    auditProject.setArtifactFilter(null);
    auditProject.setManagedVersionMap(null);
    return auditProject;
  }

  private static List<Dependency> toDependencies(
      final List<BanishedDependencyOriginalModel.DependencyEntry> entries) {
    final List<Dependency> dependencies = new ArrayList<>(entries.size());
    entries.stream().map(MavenOriginalInputProject::toDependency).forEach(dependencies::add);
    return dependencies;
  }

  @SuppressWarnings("PMD.AvoidInstantiatingObjectsInLoops")
  private static Dependency toDependency(
      final BanishedDependencyOriginalModel.DependencyEntry entry) {
    final Dependency dependency = new Dependency();
    dependency.setGroupId(entry.groupId());
    dependency.setArtifactId(entry.artifactId());
    setIfPresent(entry.version(), dependency::setVersion);
    setIfPresent(entry.type(), dependency::setType);
    setIfPresent(entry.classifier(), dependency::setClassifier);
    setIfPresent(entry.scope(), dependency::setScope);
    setIfPresent(entry.optional(), dependency::setOptional);
    setIfPresent(entry.systemPath(), dependency::setSystemPath);
    for (final BanishedDependencyOriginalModel.ExclusionEntry source : entry.exclusions()) {
      final Exclusion exclusion = new Exclusion();
      exclusion.setGroupId(source.groupId());
      exclusion.setArtifactId(source.artifactId());
      dependency.addExclusion(exclusion);
    }
    return dependency;
  }

  private static DependencyManagement toManagement(
      final List<BanishedDependencyOriginalModel.DependencyEntry> entries) {
    final DependencyManagement management = new DependencyManagement();
    management.setDependencies(toDependencies(entries));
    return management;
  }

  private static void setIfPresent(
      final String value, final java.util.function.Consumer<String> setter) {
    if (!value.isEmpty()) {
      setter.accept(value);
    }
  }
}
