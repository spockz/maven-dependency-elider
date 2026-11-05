/* WHY: Stores decisions for report replay. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.AssessmentIntent;
import io.github.spockz.elider.model.ClaimGroupStatus;
import io.github.spockz.elider.model.CodeAttributionResolver;
import io.github.spockz.elider.model.CodeReference;
import io.github.spockz.elider.model.PrerequisiteClaim;
import io.github.spockz.elider.model.VersionApplicability;
import io.github.spockz.elider.model.VersionCoverageClaim;
import io.github.spockz.elider.model.VulnerabilityFindingContribution;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/** Generic decision and selected evidence for one Maven component. */
record GenericFindingAssessment(
    String vulnerabilityId,
    Set<String> aliases,
    ArtifactCoordinate candidate,
    VersionApplicability applicability,
    Optional<AssessmentIntent> intent,
    ClaimGroupStatus codeGroupStatus,
    List<CodeAttributionResolver.DeclarationResult> codeAttribution,
    List<CodeReference> heuristicLeads,
    ClaimGroupStatus prerequisiteGroupStatus,
    List<PrerequisiteClaim> effectivePrerequisites,
    List<VersionCoverageClaim> unresolvedVersionClaims,
    Set<String> overriddenFields,
    Set<String> enrichedFields,
    Outcome outcome,
    String detail,
    MavenVulnerabilityAssessment.InventoryDisposition inventoryDisposition,
    List<VulnerabilityFindingContribution> contributions) {
  GenericFindingAssessment {
    requireText(vulnerabilityId, "vulnerabilityId");
    aliases = Set.copyOf(Objects.requireNonNull(aliases, "aliases"));
    Objects.requireNonNull(candidate, "candidate");
    Objects.requireNonNull(applicability, "applicability");
    Objects.requireNonNull(intent, "intent");
    Objects.requireNonNull(codeGroupStatus, "codeGroupStatus");
    codeAttribution = List.copyOf(Objects.requireNonNull(codeAttribution, "codeAttribution"));
    heuristicLeads = List.copyOf(Objects.requireNonNull(heuristicLeads, "heuristicLeads"));
    Objects.requireNonNull(prerequisiteGroupStatus, "prerequisiteGroupStatus");
    effectivePrerequisites =
        List.copyOf(Objects.requireNonNull(effectivePrerequisites, "effectivePrerequisites"));
    unresolvedVersionClaims =
        List.copyOf(Objects.requireNonNull(unresolvedVersionClaims, "unresolvedVersionClaims"));
    overriddenFields = Set.copyOf(Objects.requireNonNull(overriddenFields, "overriddenFields"));
    enrichedFields = Set.copyOf(Objects.requireNonNull(enrichedFields, "enrichedFields"));
    Objects.requireNonNull(outcome, "outcome");
    requireText(detail, "detail");
    Objects.requireNonNull(inventoryDisposition, "inventoryDisposition");
    contributions = List.copyOf(Objects.requireNonNull(contributions, "contributions"));
  }

  /** Final assessment disposition saved without rerunning proof. */
  /* package */ enum Outcome {
    NOT_AFFECTED,
    UNRESOLVED,
    REVIEW_ONLY,
    DECLARED_CODE_ABSENT,
    PREREQUISITES_ABSENT,
    NO_PROOF
  }

  private static void requireText(final String value, final String field) {
    if (value == null || value.isBlank()) {
      throw new IllegalArgumentException(field + " must not be blank");
    }
  }
}
