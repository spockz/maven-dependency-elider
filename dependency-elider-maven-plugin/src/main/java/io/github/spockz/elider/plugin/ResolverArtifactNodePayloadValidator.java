/* WHY: Validates node metadata separately from topology and store envelopes. */

package io.github.spockz.elider.plugin;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Validates detached node records and returns them indexed by identity token. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class ResolverArtifactNodePayloadValidator {
  private ResolverArtifactNodePayloadValidator() {
    throw new AssertionError("No instances");
  }

  @SuppressWarnings("PMD.UseConcurrentHashMap")
  static Map<String, Map<?, ?>> validate(final List<?> values) {
    // Linked order preserves the graph traversal's assigned node order.
    final Map<String, Map<?, ?>> nodes = new LinkedHashMap<>();
    int index = 0;
    for (final Object value : values) {
      final Map<?, ?> node = ResolverArtifactGraphPayloadChecks.map(value, "node");
      ResolverArtifactGraphPayloadChecks.fields(
          node, ResolverArtifactGraphSnapshotSchema.NODE_FIELDS, "node");
      final String nodeId =
          ResolverArtifactGraphScalarChecks.nodeId(
              node.get(ResolverArtifactGraphSnapshotSchema.NODE_ID), "node ID");
      if (!nodeId.equals("n" + index)) {
        throw ResolverArtifactGraphPayloadChecks.invalid("node IDs do not follow capture order");
      }
      index++;
      if (nodes.put(nodeId, node) != null) {
        throw ResolverArtifactGraphPayloadChecks.invalid("duplicate graph node ID");
      }
      ResolverArtifactGraphScalarChecks.bool(
          node.get(ResolverArtifactGraphSnapshotSchema.REACHABLE), "node reachability");
      ResolverArtifactArtifactPayloadValidator.artifact(
          node.get(ResolverArtifactGraphSnapshotSchema.ARTIFACT), "node artifact");
      ResolverArtifactArtifactPayloadValidator.dependency(
          node.get(ResolverArtifactGraphSnapshotSchema.DEPENDENCY));
      ResolverArtifactGraphScalarChecks.string(
          node.get(ResolverArtifactGraphSnapshotSchema.EFFECTIVE_SCOPE), "effective scope", true);
      ResolverArtifactGraphScalarChecks.integer(
          node.get(ResolverArtifactGraphSnapshotSchema.MANAGED_BITS), "managed bits");
      ResolverArtifactGraphScalarChecks.string(
          node.get(ResolverArtifactGraphSnapshotSchema.VERSION_CONSTRAINT),
          "version constraint",
          true);
      ResolverArtifactGraphScalarChecks.string(
          node.get(ResolverArtifactGraphSnapshotSchema.VERSION), "version", true);
      ResolverArtifactGraphScalarChecks.bool(
          node.get(ResolverArtifactGraphSnapshotSchema.CHILDREN_PRESENT), "children presence");
      ResolverArtifactArtifactPayloadValidator.list(
          node.get(ResolverArtifactGraphSnapshotSchema.ALIASES),
          ResolverArtifactGraphSnapshotSchema.ALIASES);
      ResolverArtifactArtifactPayloadValidator.list(
          node.get(ResolverArtifactGraphSnapshotSchema.RELOCATIONS),
          ResolverArtifactGraphSnapshotSchema.RELOCATIONS);
      validateConflict(node);
    }
    return nodes;
  }

  private static void validateConflict(final Map<?, ?> node) {
    validateWinnerMetadata(node);
    validateOriginalMetadata(node);
  }

  private static void validateWinnerMetadata(final Map<?, ?> node) {
    ResolverArtifactGraphScalarChecks.bool(
        node.get(ResolverArtifactGraphSnapshotSchema.CONFLICT_WINNER_PRESENT),
        "conflict winner presence");
    ResolverArtifactGraphScalarChecks.string(
        node.get(ResolverArtifactGraphSnapshotSchema.CONFLICT_WINNER_NODE_ID),
        "conflict winner node ID",
        true);
    ResolverArtifactArtifactPayloadValidator.artifact(
        node.get(ResolverArtifactGraphSnapshotSchema.CONFLICT_WINNER_EXTERNAL_ARTIFACT),
        "external conflict winner");
    ResolverArtifactGraphScalarChecks.string(
        node.get(ResolverArtifactGraphSnapshotSchema.CONFLICT_WINNER_VALUE_TYPE),
        "conflict winner value type",
        true);
    final boolean winnerPresent =
        Boolean.TRUE.equals(node.get(ResolverArtifactGraphSnapshotSchema.CONFLICT_WINNER_PRESENT));
    final boolean hasWinnerEncoding = hasWinnerEncoding(node);
    if (!winnerPresent && hasWinnerEncoding) {
      throw ResolverArtifactGraphPayloadChecks.invalid("absent conflict winner has metadata");
    }
    if (hasMutuallyExclusiveWinnerEncodings(node)) {
      throw ResolverArtifactGraphPayloadChecks.invalid(
          "conflict winner encodings are mutually exclusive");
    }
  }

  private static boolean hasWinnerEncoding(final Map<?, ?> node) {
    return node.get(ResolverArtifactGraphSnapshotSchema.CONFLICT_WINNER_NODE_ID) != null
        || node.get(ResolverArtifactGraphSnapshotSchema.CONFLICT_WINNER_EXTERNAL_ARTIFACT) != null
        || node.get(ResolverArtifactGraphSnapshotSchema.CONFLICT_WINNER_VALUE_TYPE) != null;
  }

  private static boolean hasMutuallyExclusiveWinnerEncodings(final Map<?, ?> node) {
    final boolean hasNodeId =
        node.get(ResolverArtifactGraphSnapshotSchema.CONFLICT_WINNER_NODE_ID) != null;
    final boolean hasExternalArtifact =
        node.get(ResolverArtifactGraphSnapshotSchema.CONFLICT_WINNER_EXTERNAL_ARTIFACT) != null;
    final boolean hasValueType =
        node.get(ResolverArtifactGraphSnapshotSchema.CONFLICT_WINNER_VALUE_TYPE) != null;
    return (hasNodeId && (hasExternalArtifact || hasValueType))
        || (hasExternalArtifact && hasValueType);
  }

  private static void validateOriginalMetadata(final Map<?, ?> node) {
    validateOriginalScope(node);
    validateOriginalOptionality(node);
  }

  private static void validateOriginalScope(final Map<?, ?> node) {
    ResolverArtifactGraphScalarChecks.bool(
        node.get(ResolverArtifactGraphSnapshotSchema.ORIGINAL_SCOPE_PRESENT),
        "original scope presence");
    ResolverArtifactGraphScalarChecks.string(
        node.get(ResolverArtifactGraphSnapshotSchema.ORIGINAL_SCOPE), "original scope", true);
    if (!Boolean.TRUE.equals(node.get(ResolverArtifactGraphSnapshotSchema.ORIGINAL_SCOPE_PRESENT))
        && node.get(ResolverArtifactGraphSnapshotSchema.ORIGINAL_SCOPE) != null) {
      throw ResolverArtifactGraphPayloadChecks.invalid("absent original scope has a value");
    }
  }

  private static void validateOriginalOptionality(final Map<?, ?> node) {
    ResolverArtifactGraphScalarChecks.bool(
        node.get(ResolverArtifactGraphSnapshotSchema.ORIGINAL_OPTIONALITY_PRESENT),
        "original optionality presence");
    final Object optionality = node.get(ResolverArtifactGraphSnapshotSchema.ORIGINAL_OPTIONALITY);
    if (optionality != null && !(optionality instanceof Boolean || optionality instanceof String)) {
      throw ResolverArtifactGraphPayloadChecks.invalid(
          "original optionality must be null, boolean, or string");
    }
    if (!Boolean.TRUE.equals(
            node.get(ResolverArtifactGraphSnapshotSchema.ORIGINAL_OPTIONALITY_PRESENT))
        && optionality != null) {
      throw ResolverArtifactGraphPayloadChecks.invalid("absent original optionality has a value");
    }
  }
}
