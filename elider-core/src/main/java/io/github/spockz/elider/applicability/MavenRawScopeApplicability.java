/* WHY: Centralizes tri-state results shared by the raw source-scope evaluators. */

package io.github.spockz.elider.applicability;

import io.github.spockz.elider.model.CveAffectedEntryContext;
import io.github.spockz.elider.model.OsvAffectedPackage;
import io.github.spockz.elider.model.OsvAffectedRange;
import java.util.List;
import java.util.Objects;

/** Shares tri-state results across raw OSV and CNA evaluators. */
public final class MavenRawScopeApplicability {
  /** Outcome used before any report projection. */
  public enum Status {
    AFFECTED,
    UNAFFECTED,
    UNKNOWN
  }

  /** Result and explanation from raw version claims. */
  public record Result(Status status, String rationale) {}

  private MavenRawScopeApplicability() {}

  /** Evaluates one OSV package's raw claims. */
  public static Result evaluateOsv(final OsvAffectedPackage affectedPackage, final String version) {
    Objects.requireNonNull(affectedPackage, "affectedPackage");
    return OsvRawScopeEvaluator.evaluate(affectedPackage, version);
  }

  /** Evaluates raw OSV claims when a report payload has no package coordinate. */
  public static Result evaluateOsvClaims(
      final String ecosystem,
      final List<String> versions,
      final List<OsvAffectedRange> ranges,
      final String version) {
    return OsvRawScopeEvaluator.evaluateClaims(ecosystem, versions, ranges, version);
  }

  /** Evaluates one CNA entry's raw claims. */
  public static Result evaluateCna(final CveAffectedEntryContext entry, final String version) {
    Objects.requireNonNull(entry, "entry");
    return CnaRawScopeEvaluator.evaluate(entry, version);
  }

  /** Requires OSV and one exact CNA entry to agree that the candidate is affected. */
  public static Result evaluateStructured(
      final OsvAffectedPackage osvPackage,
      final CveAffectedEntryContext cnaEntry,
      final String version) {
    final Result osv = evaluateOsv(osvPackage, version);
    final Result cna = evaluateCna(cnaEntry, version);
    if (osv.status() == Status.AFFECTED && cna.status() == Status.AFFECTED) {
      return affected("OSV and the exact CNA product entry both mark the version affected");
    }
    if (osv.status() == Status.UNAFFECTED && cna.status() == Status.UNAFFECTED) {
      return unaffected("OSV and the exact CNA product entry both mark the version unaffected");
    }
    return unknown("OSV and CNA raw version claims do not establish one matching status");
  }

  /** Validates a concrete candidate using Maven's version-range parser. */
  public static boolean validVersion(final String version) {
    if (version == null || version.isBlank()) {
      return false;
    }
    try {
      MavenVersionRangeMatcher.validate("[" + version + "]");
      return true;
    } catch (final IllegalArgumentException exception) {
      return false;
    }
  }

  /** Builds an affected result. */
  /* package */ static Result affected(final String rationale) {
    return new Result(Status.AFFECTED, rationale);
  }

  /** Builds an unaffected result. */
  /* package */ static Result unaffected(final String rationale) {
    return new Result(Status.UNAFFECTED, rationale);
  }

  /** Builds an unresolved result. */
  /* package */ static Result unknown(final String rationale) {
    return new Result(Status.UNKNOWN, rationale);
  }
}
