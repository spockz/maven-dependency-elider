/* WHY: Names and exact field sets define the JDK-only graph payload shared across Maven realms. */

package io.github.spockz.elider.plugin;

import java.util.Set;

/** Field names and exact schemas for graph snapshot payloads. */
@SuppressWarnings({"PMD.CommentDefaultAccessModifier", "PMD.CommentRequired"})
final class ResolverArtifactGraphSnapshotSchema {
  static final String GRAPH_FINGERPRINT = "graphFingerprint";
  static final String PROJECT_KEY = "projectKey";
  static final String PLAN_PRESENT = "planPresent";
  static final String PLAN_FINGERPRINT = "planFingerprint";
  static final String PLAN_GENERATION = "planGeneration";
  static final String CAPTURE_GENERATION = "captureGeneration";
  static final String ROOT_NODE_ID = "rootNodeId";
  static final String NODES = "nodes";
  static final String EDGES = "edges";
  static final String NODE_ID = "id";
  static final String REACHABLE = "reachable";
  static final String ARTIFACT = "artifact";
  static final String DEPENDENCY = "dependency";
  static final String EFFECTIVE_SCOPE = "effectiveScope";
  static final String MANAGED_BITS = "managedBits";
  static final String VERSION_CONSTRAINT = "versionConstraint";
  static final String VERSION = "version";
  static final String CHILDREN_PRESENT = "childrenPresent";
  static final String ALIASES = "aliases";
  static final String RELOCATIONS = "relocations";
  static final String CONFLICT_WINNER_PRESENT = "conflictWinnerPresent";
  static final String CONFLICT_WINNER_NODE_ID = "conflictWinnerNodeId";
  static final String CONFLICT_WINNER_EXTERNAL_ARTIFACT = "conflictWinnerExternalArtifact";
  static final String CONFLICT_WINNER_VALUE_TYPE = "conflictWinnerValueType";
  static final String ORIGINAL_SCOPE_PRESENT = "originalScopePresent";
  static final String ORIGINAL_SCOPE = "originalScope";
  static final String ORIGINAL_OPTIONALITY_PRESENT = "originalOptionalityPresent";
  static final String ORIGINAL_OPTIONALITY = "originalOptionality";
  static final String GROUP_ID = "groupId";
  static final String ARTIFACT_ID = "artifactId";
  static final String BASE_VERSION = "baseVersion";
  static final String EXTENSION = "extension";
  static final String CLASSIFIER = "classifier";
  static final String PROPERTIES = "properties";
  static final String SCOPE = "scope";
  static final String OPTIONAL = "optional";
  static final String EXCLUSIONS = "exclusions";
  static final String PARENT_NODE_ID = "parentNodeId";
  static final String CHILD_NODE_ID = "childNodeId";

  static final Set<String> SNAPSHOT_FIELDS =
      Set.of(
          GRAPH_FINGERPRINT,
          PROJECT_KEY,
          PLAN_PRESENT,
          PLAN_FINGERPRINT,
          PLAN_GENERATION,
          CAPTURE_GENERATION,
          ROOT_NODE_ID,
          NODES,
          EDGES);

  static final Set<String> NODE_FIELDS =
      Set.of(
          NODE_ID,
          REACHABLE,
          ARTIFACT,
          DEPENDENCY,
          EFFECTIVE_SCOPE,
          MANAGED_BITS,
          VERSION_CONSTRAINT,
          VERSION,
          CHILDREN_PRESENT,
          ALIASES,
          RELOCATIONS,
          CONFLICT_WINNER_PRESENT,
          CONFLICT_WINNER_NODE_ID,
          CONFLICT_WINNER_EXTERNAL_ARTIFACT,
          CONFLICT_WINNER_VALUE_TYPE,
          ORIGINAL_SCOPE_PRESENT,
          ORIGINAL_SCOPE,
          ORIGINAL_OPTIONALITY_PRESENT,
          ORIGINAL_OPTIONALITY);

  static final Set<String> ARTIFACT_FIELDS =
      Set.of(GROUP_ID, ARTIFACT_ID, VERSION, BASE_VERSION, EXTENSION, CLASSIFIER, PROPERTIES);

  static final Set<String> DEPENDENCY_FIELDS = Set.of(ARTIFACT, SCOPE, OPTIONAL, EXCLUSIONS);

  static final Set<String> EXCLUSION_FIELDS = Set.of(GROUP_ID, ARTIFACT_ID, CLASSIFIER, EXTENSION);

  static final Set<String> EDGE_FIELDS = Set.of(PARENT_NODE_ID, CHILD_NODE_ID);

  private ResolverArtifactGraphSnapshotSchema() {
    throw new AssertionError("No instances");
  }
}
