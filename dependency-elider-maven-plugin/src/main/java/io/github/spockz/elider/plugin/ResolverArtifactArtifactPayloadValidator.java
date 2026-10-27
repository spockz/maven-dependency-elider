/* WHY: Validates Resolver artifact, dependency, and exclusion values independently. */

package io.github.spockz.elider.plugin;

import java.util.List;
import java.util.Map;

/** Validates artifact-shaped values in a detached graph snapshot. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class ResolverArtifactArtifactPayloadValidator {
  private ResolverArtifactArtifactPayloadValidator() {
    throw new AssertionError("No instances");
  }

  static void dependency(final Object value) {
    if (value == null) {
      return;
    }
    final Map<?, ?> dependency =
        ResolverArtifactGraphPayloadChecks.map(
            value, ResolverArtifactGraphSnapshotSchema.DEPENDENCY);
    ResolverArtifactGraphPayloadChecks.fields(
        dependency,
        ResolverArtifactGraphSnapshotSchema.DEPENDENCY_FIELDS,
        ResolverArtifactGraphSnapshotSchema.DEPENDENCY);
    artifact(dependency.get(ResolverArtifactGraphSnapshotSchema.ARTIFACT), "dependency artifact");
    ResolverArtifactGraphPayloadChecks.string(
        dependency.get(ResolverArtifactGraphSnapshotSchema.SCOPE), "dependency scope", true);
    ResolverArtifactGraphPayloadChecks.bool(
        dependency.get(ResolverArtifactGraphSnapshotSchema.OPTIONAL), "dependency optionality");
    for (final Object valueEntry :
        ResolverArtifactGraphPayloadChecks.list(
            dependency.get(ResolverArtifactGraphSnapshotSchema.EXCLUSIONS),
            ResolverArtifactGraphSnapshotSchema.EXCLUSIONS)) {
      exclusion(valueEntry);
    }
  }

  static void list(final Object value, final String field) {
    for (final Object entry : ResolverArtifactGraphPayloadChecks.list(value, field)) {
      if (entry == null) {
        throw ResolverArtifactGraphPayloadChecks.invalid(field + " cannot contain a null artifact");
      }
      artifact(entry, field + " artifact");
    }
  }

  static void artifact(final Object value, final String field) {
    if (value == null) {
      return;
    }
    final Map<?, ?> artifact = ResolverArtifactGraphPayloadChecks.map(value, field);
    ResolverArtifactGraphPayloadChecks.fields(
        artifact, ResolverArtifactGraphSnapshotSchema.ARTIFACT_FIELDS, field);
    for (final String coordinate :
        List.of(
            ResolverArtifactGraphSnapshotSchema.GROUP_ID,
            ResolverArtifactGraphSnapshotSchema.ARTIFACT_ID,
            ResolverArtifactGraphSnapshotSchema.VERSION,
            ResolverArtifactGraphSnapshotSchema.BASE_VERSION,
            ResolverArtifactGraphSnapshotSchema.EXTENSION,
            ResolverArtifactGraphSnapshotSchema.CLASSIFIER)) {
      ResolverArtifactGraphPayloadChecks.string(
          artifact.get(coordinate), field + " " + coordinate, true);
    }
    final Object propertiesValue = artifact.get(ResolverArtifactGraphSnapshotSchema.PROPERTIES);
    if (propertiesValue != null) {
      final Map<?, ?> properties =
          ResolverArtifactGraphPayloadChecks.map(
              propertiesValue, ResolverArtifactGraphSnapshotSchema.PROPERTIES);
      properties.forEach(
          (key, property) -> {
            ResolverArtifactGraphPayloadChecks.string(key, "artifact property key", false);
            ResolverArtifactGraphPayloadChecks.string(property, "artifact property value", true);
          });
    }
  }

  private static void exclusion(final Object value) {
    final Map<?, ?> exclusion = ResolverArtifactGraphPayloadChecks.map(value, "exclusion");
    ResolverArtifactGraphPayloadChecks.fields(
        exclusion, ResolverArtifactGraphSnapshotSchema.EXCLUSION_FIELDS, "exclusion");
    for (final String coordinate :
        List.of(
            ResolverArtifactGraphSnapshotSchema.GROUP_ID,
            ResolverArtifactGraphSnapshotSchema.ARTIFACT_ID,
            ResolverArtifactGraphSnapshotSchema.CLASSIFIER,
            ResolverArtifactGraphSnapshotSchema.EXTENSION)) {
      ResolverArtifactGraphPayloadChecks.string(
          exclusion.get(coordinate), "exclusion " + coordinate, false);
    }
  }
}
