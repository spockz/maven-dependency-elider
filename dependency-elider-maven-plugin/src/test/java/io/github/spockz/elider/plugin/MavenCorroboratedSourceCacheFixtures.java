// WHY: Builds stale cached corroboration rows to verify assessment recomputes them from current
// bytes.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.AdvisoryEvidence;
import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.CorroboratedSourceClassCandidate;
import io.github.spockz.elider.model.OsvAdvisoryRecord;
import io.github.spockz.elider.model.StructuredSourceClassEvidence;
import java.util.ArrayList;
import java.util.List;

/** Creates a stale corroboration row for assessment-boundary tests. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class MavenCorroboratedSourceCacheFixtures {
  private MavenCorroboratedSourceCacheFixtures() {}

  static OsvAdvisoryRecord withStaleCorroboratedCandidate(final OsvAdvisoryRecord record) {
    final StructuredSourceClassEvidence structured = structuredEvidence(record);
    final List<AdvisoryEvidence> evidence = new ArrayList<>(record.evidence());
    evidence.add(staleCandidate(structured));
    return new OsvAdvisoryRecord(
        record.osvId(),
        record.aliases(),
        record.affectedPackages(),
        record.cnaAffectedEntries(),
        evidence);
  }

  private static StructuredSourceClassEvidence structuredEvidence(final OsvAdvisoryRecord record) {
    return record.evidence().stream()
        .filter(StructuredSourceClassEvidence.class::isInstance)
        .map(StructuredSourceClassEvidence.class::cast)
        .findFirst()
        .orElseThrow();
  }

  private static CorroboratedSourceClassCandidate staleCandidate(
      final StructuredSourceClassEvidence structured) {
    return new CorroboratedSourceClassCandidate(
        structured.scope(),
        structured.provenance(),
        "containers.cna.affected[1]",
        ArtifactCoordinate.of(
            MavenCorroboratedSourceArchiveFixtures.GROUP_ID,
            MavenCorroboratedSourceArchiveFixtures.ARTIFACT_ID,
            MavenCorroboratedSourceArchiveFixtures.VERSION),
        "d".repeat(64),
        "org/example/Outer.class",
        0,
        structured.affectedProductIdentity(),
        MavenCorroboratedSourceArchiveFixtures.PROGRAM_FILE,
        "org.example.Outer",
        "Outer.java",
        "cached source lead from prior artifact bytes",
        false,
        CorroboratedSourceClassCandidate.MappingStatus.INCOMPLETE_REVIEW_ONLY);
  }
}
