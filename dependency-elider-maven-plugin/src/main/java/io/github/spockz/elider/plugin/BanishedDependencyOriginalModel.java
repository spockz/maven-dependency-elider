// WHY: Preserves classloader-neutral original dependency declarations before global exclusions.

package io.github.spockz.elider.plugin;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import org.apache.maven.model.Dependency;
import org.apache.maven.model.DependencyManagement;
import org.apache.maven.model.Model;
import org.apache.maven.model.Profile;
import org.apache.maven.project.MavenProject;

/** Detached Maven declarations and their exclusion policy. */
record BanishedDependencyOriginalModel(
    ProjectIdentity project,
    List<ExecutionPolicy> executions,
    List<String> banishedDependencies,
    List<DependencyEntry> effectiveDependencies,
    List<DependencyEntry> originalDependencies,
    List<DependencyEntry> effectiveManagement,
    List<DependencyEntry> originalManagement,
    ExclusionRecommendations.Snapshot exclusionProvenance,
    String sourceFingerprint) {
  BanishedDependencyOriginalModel {
    Objects.requireNonNull(project, "project");
    executions = List.copyOf(Objects.requireNonNull(executions, "executions"));
    banishedDependencies = List.copyOf(Objects.requireNonNull(banishedDependencies, "bans"));
    effectiveDependencies =
        List.copyOf(Objects.requireNonNull(effectiveDependencies, "dependencies"));
    originalDependencies =
        List.copyOf(Objects.requireNonNull(originalDependencies, "originalDependencies"));
    effectiveManagement = List.copyOf(Objects.requireNonNull(effectiveManagement, "management"));
    originalManagement =
        List.copyOf(Objects.requireNonNull(originalManagement, "originalManagement"));
    Objects.requireNonNull(exclusionProvenance, "exclusionProvenance");
    Objects.requireNonNull(sourceFingerprint, "sourceFingerprint");
    if (!sourceFingerprint.matches("[0-9a-f]{64}")) {
      throw new IllegalArgumentException("sourceFingerprint must be a lowercase SHA-256 value");
    }
  }

  /* package */ static BanishedDependencyOriginalModel capture(
      final MavenProject project, final List<ExecutionPolicy> executions, final List<String> bans) {
    final ProjectIdentity identity = projectIdentity(project);
    final List<DependencyEntry> effectiveDependencies =
        dependencyEntries("effective-dependencies", project.getDependencies());
    final Model original = project.getOriginalModel();
    final List<DependencyEntry> originalDependencies = new ArrayList<>();
    final List<DependencyEntry> originalManagement = new ArrayList<>();
    if (original != null) {
      originalDependencies.addAll(
          dependencyEntries("original-model-dependencies", original.getDependencies()));
      originalManagement.addAll(
          dependencyManagementEntries(
              "original-model-management", original.getDependencyManagement()));
      for (final Profile profile : original.getProfiles()) {
        final String profileId = profile.getId() == null ? "" : profile.getId();
        originalDependencies.addAll(
            dependencyEntries(
                "original-profile:" + profileId + ":dependencies", profile.getDependencies()));
        originalManagement.addAll(
            dependencyManagementEntries(
                "original-profile:" + profileId + ":management",
                profile.getDependencyManagement()));
      }
    }
    final List<DependencyEntry> effectiveManagement =
        dependencyManagementEntries("effective-management", project.getDependencyManagement());
    for (final Profile profile : project.getActiveProfiles()) {
      final String profileId = profile.getId() == null ? "" : profile.getId();
      originalDependencies.addAll(
          dependencyEntries(
              "active-profile:" + profileId + ":dependencies", profile.getDependencies()));
      originalManagement.addAll(
          dependencyManagementEntries(
              "active-profile:" + profileId + ":management", profile.getDependencyManagement()));
    }
    final List<String> fingerprintFields = new ArrayList<>();
    addFingerprintEntries(fingerprintFields, "effective-dependencies", effectiveDependencies);
    addFingerprintEntries(fingerprintFields, "original-dependencies", originalDependencies);
    addFingerprintEntries(fingerprintFields, "effective-management", effectiveManagement);
    addFingerprintEntries(fingerprintFields, "original-management", originalManagement);
    final ExclusionRecommendations.Snapshot exclusionProvenance =
        ExclusionProvenanceCapture.capture(project);
    addProvenanceFingerprint(fingerprintFields, exclusionProvenance);
    return new BanishedDependencyOriginalModel(
        identity,
        executions,
        bans,
        effectiveDependencies,
        originalDependencies,
        effectiveManagement,
        originalManagement,
        exclusionProvenance,
        MavenElisionGraphBinding.sha256(fingerprintFields));
  }

  private static void addProvenanceFingerprint(
      final List<String> fields, final ExclusionRecommendations.Snapshot snapshot) {
    for (final List<ExclusionRecommendations.Declaration> declarations :
        List.of(snapshot.dependencies(), snapshot.management())) {
      fields.add(Integer.toString(declarations.size()));
      for (final ExclusionRecommendations.Declaration declaration : declarations) {
        final ExclusionRecommendations.Reference ref = declaration.reference();
        fields.addAll(
            List.of(
                Integer.toString(ref.ordinal()),
                ref.groupId(),
                ref.artifactId(),
                ref.type(),
                ref.classifier()));
        addOriginFingerprint(fields, ref.origin());
        fields.add(Integer.toString(declaration.exclusions().size()));
        for (final ExclusionRecommendations.Exclusion exclusion : declaration.exclusions()) {
          fields.add(exclusion.coordinate().groupId());
          fields.add(exclusion.coordinate().artifactId());
          addOriginFingerprint(fields, exclusion.origin());
        }
      }
    }
    fields.add(Integer.toString(snapshot.diagnostics().size()));
    fields.addAll(snapshot.diagnostics());
  }

  private static void addOriginFingerprint(
      final List<String> fields, final ExclusionRecommendations.Origin origin) {
    fields.addAll(
        List.of(
            origin.kind(),
            origin.modelId(),
            origin.source(),
            Integer.toString(origin.line()),
            Integer.toString(origin.column()),
            origin.profileId()));
  }

  /* package */ BanishedDependencyOriginalModel withExpectedInjections() {
    final List<DependencyEntry> injected =
        effectiveDependencies.stream()
            .map(entry -> entry.withBanExclusions(banishedDependencies))
            .toList();
    return new BanishedDependencyOriginalModel(
        project,
        executions,
        banishedDependencies,
        injected,
        originalDependencies,
        effectiveManagement,
        originalManagement,
        exclusionProvenance,
        sourceFingerprint);
  }

  /* package */ boolean hasSameCaptureSource(final BanishedDependencyOriginalModel other) {
    return other != null
        && project.equals(other.project)
        && executions.equals(other.executions)
        && banishedDependencies.equals(other.banishedDependencies)
        && originalDependencies.equals(other.originalDependencies)
        && effectiveManagement.equals(other.effectiveManagement)
        && originalManagement.equals(other.originalManagement)
        && sourceFingerprint.equals(other.sourceFingerprint);
  }

  /* package */ boolean hasValidSourceFingerprint() {
    final List<String> fields = new ArrayList<>();
    addFingerprintEntries(fields, "effective-dependencies", effectiveDependencies);
    addFingerprintEntries(fields, "original-dependencies", originalDependencies);
    addFingerprintEntries(fields, "effective-management", effectiveManagement);
    addFingerprintEntries(fields, "original-management", originalManagement);
    addProvenanceFingerprint(fields, exclusionProvenance);
    return sourceFingerprint.equals(MavenElisionGraphBinding.sha256(fields));
  }

  /* package */ boolean matchesCurrentModel(final BanishedDependencyOriginalModel current) {
    return current != null
        && project.equals(current.project)
        && executions.equals(current.executions)
        && banishedDependencies.equals(current.banishedDependencies)
        && withExpectedInjections().effectiveDependencies.equals(current.effectiveDependencies)
        && originalDependencies.equals(current.originalDependencies)
        && effectiveManagement.equals(current.effectiveManagement)
        && originalManagement.equals(current.originalManagement)
        && sameOriginalProvenance(current.exclusionProvenance);
  }

  private boolean sameOriginalProvenance(final ExclusionRecommendations.Snapshot current) {
    if (!exclusionProvenance.management().equals(current.management())
        || exclusionProvenance.dependencies().size() != current.dependencies().size()) {
      return false;
    }
    for (int index = 0; index < exclusionProvenance.dependencies().size(); index++) {
      final ExclusionRecommendations.Declaration original =
          exclusionProvenance.dependencies().get(index);
      final ExclusionRecommendations.Declaration actual = current.dependencies().get(index);
      if (!original.reference().equals(actual.reference())
          || actual.exclusions().size() < original.exclusions().size()
          || !original
              .exclusions()
              .equals(actual.exclusions().subList(0, original.exclusions().size()))) {
        return false;
      }
    }
    return true;
  }

  @SuppressWarnings("PMD.LawOfDemeter")
  /* package */ static ProjectIdentity projectIdentity(final MavenProject project) {
    final Path baseDirectory = project.getBasedir() == null ? null : project.getBasedir().toPath();
    if (baseDirectory == null) {
      throw new IllegalArgumentException("Cannot capture ban exclusions without project basedir");
    }
    return new ProjectIdentity(
        baseDirectory.toAbsolutePath().normalize().toString(),
        project.getGroupId(),
        project.getArtifactId(),
        project.getVersion());
  }

  private static List<DependencyEntry> dependencyManagementEntries(
      final String provenance, final DependencyManagement management) {
    return management == null
        ? List.of()
        : dependencyEntries(provenance, management.getDependencies());
  }

  private static List<DependencyEntry> dependencyEntries(
      final String provenance, final List<Dependency> dependencies) {
    if (dependencies == null) {
      return List.of();
    }
    final List<DependencyEntry> entries = new ArrayList<>();
    for (int index = 0; index < dependencies.size(); index++) {
      entries.add(dependencyEntry(provenance, index, dependencies.get(index)));
    }
    return List.copyOf(entries);
  }

  private static DependencyEntry dependencyEntry(
      final String provenance, final int ordinal, final Dependency dependency) {
    final List<ExclusionEntry> exclusions =
        dependency.getExclusions().stream()
            .map(exclusion -> exclusionEntry(exclusion.getGroupId(), exclusion.getArtifactId()))
            .toList();
    return new DependencyEntry(
        provenance,
        ordinal,
        dependency.getGroupId(),
        dependency.getArtifactId(),
        dependency.getVersion(),
        dependency.getType(),
        dependency.getClassifier(),
        dependency.getScope(),
        dependency.getOptional(),
        dependency.getSystemPath(),
        exclusions);
  }

  private static ExclusionEntry exclusionEntry(final String groupId, final String artifactId) {
    return new ExclusionEntry(groupId, artifactId);
  }

  private static void addFingerprintEntries(
      final List<String> fields, final String source, final List<DependencyEntry> entries) {
    fields.add(source);
    fields.add(Integer.toString(entries.size()));
    for (final DependencyEntry entry : entries) {
      fields.addAll(
          Arrays.asList(
              entry.provenance(),
              Integer.toString(entry.ordinal()),
              entry.groupId(),
              entry.artifactId(),
              entry.version(),
              entry.type(),
              entry.classifier(),
              entry.scope(),
              entry.optional(),
              entry.systemPath(),
              Integer.toString(entry.exclusions().size())));
      for (final ExclusionEntry exclusion : entry.exclusions()) {
        fields.add(exclusion.groupId());
        fields.add(exclusion.artifactId());
      }
    }
  }

  /* package */ record ProjectIdentity(
      String basedir, String groupId, String artifactId, String version) {
    ProjectIdentity {
      basedir = require(basedir, "basedir");
      groupId = nullable(groupId);
      artifactId = require(artifactId, "artifactId");
      version = nullable(version);
    }
  }

  /* package */ record ExecutionPolicy(
      String executionId,
      String goal,
      String pluginVersion,
      String phase,
      String source,
      List<String> bans) {
    ExecutionPolicy {
      executionId = require(executionId, "executionId");
      goal = require(goal, "goal");
      pluginVersion = require(pluginVersion, "pluginVersion");
      phase = require(phase, "phase");
      source = require(source, "source");
      bans = List.copyOf(Objects.requireNonNull(bans, "bans"));
    }
  }

  /* package */ record DependencyEntry(
      String provenance,
      int ordinal,
      String groupId,
      String artifactId,
      String version,
      String type,
      String classifier,
      String scope,
      String optional,
      String systemPath,
      List<ExclusionEntry> exclusions) {
    DependencyEntry {
      provenance = require(provenance, "provenance");
      groupId = nullable(groupId);
      artifactId = nullable(artifactId);
      version = nullable(version);
      type = nullable(type);
      classifier = nullable(classifier);
      scope = nullable(scope);
      optional = nullable(optional);
      systemPath = nullable(systemPath);
      exclusions = List.copyOf(Objects.requireNonNull(exclusions, "exclusions"));
    }

    /* package */ DependencyEntry withBanExclusions(final List<String> bans) {
      final List<ExclusionEntry> updated = new ArrayList<>(exclusions);
      for (final String ban : bans) {
        final String[] coordinate = ban.split(":", -1);
        final ExclusionEntry exclusion = exclusionEntry(coordinate[0], coordinate[1]);
        if (!updated.contains(exclusion)) {
          updated.add(exclusion);
        }
      }
      return new DependencyEntry(
          provenance,
          ordinal,
          groupId,
          artifactId,
          version,
          type,
          classifier,
          scope,
          optional,
          systemPath,
          updated);
    }
  }

  /* package */ record ExclusionEntry(String groupId, String artifactId) {
    ExclusionEntry {
      groupId = require(groupId, "exclusion.groupId");
      artifactId = require(artifactId, "exclusion.artifactId");
    }
  }

  private static String require(final String value, final String name) {
    if (value == null || value.isBlank()) {
      throw new IllegalArgumentException(name + " must not be blank");
    }
    return value;
  }

  private static String nullable(final String value) {
    return value == null ? "" : value;
  }
}
