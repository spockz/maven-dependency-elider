// WHY: Keeps each policy observation and its evidence intact for later report replay.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.advisory.ForbiddenSymbol;
import io.github.spockz.elider.model.AdvisoryProvenance;
import io.github.spockz.elider.model.EvidenceOrigin;
import io.github.spockz.elider.model.MavenVersionRangeMatcher;
import io.github.spockz.elider.model.MultiReleaseEntryPath;
import java.net.URI;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;
import org.objectweb.asm.Type;

@SuppressWarnings({"PMD.CommentDefaultAccessModifier", "PMD.CommentRequired"})
record ForbiddenCodeAssessment(
    String cveId,
    String symbol,
    ComponentKind componentKind,
    String componentIdentity,
    String versionScope,
    String componentVersion,
    Integer targetRelease,
    boolean assertsAffected,
    VersionApplicability versionApplicability,
    Mode mode,
    Status status,
    String evidenceKind,
    String provider,
    List<Match> matches,
    boolean complete,
    String reason,
    String provenance,
    String sourceUrl,
    boolean enforcementEnabled) {
  static final String DIRECT_RUNTIME_CALL = "DIRECT_RUNTIME_CALL";
  private static final Pattern CVE = Pattern.compile("CVE-[0-9]{4}-[0-9]{4,}");
  private static final String FIELD_DESCRIPTOR = "\\[*[BCDFIJSZ]|\\[*L[^.;\\[()]+;";
  private static final Pattern METHOD_DESCRIPTOR =
      Pattern.compile("\\((?:" + FIELD_DESCRIPTOR + ")*\\)(?:V|" + FIELD_DESCRIPTOR + ")");
  private static final Set<String> EVIDENCE_KINDS =
      Set.of(
          "PHYSICAL_DECLARATIONS",
          "STAGED_ARCHIVE_DECLARATIONS",
          "CACHED_ARCHIVE_DECLARATIONS",
          "EFFECTIVE_COMPONENT_INVENTORY",
          "INCOMPLETE_SCOPE",
          "VERSION_SCOPE",
          "RUNTIME_REACHABILITY",
          DIRECT_RUNTIME_CALL);

  enum ComponentKind {
    MAVEN_ARTIFACT,
    PROJECT_OUTPUT,
    JAVA_RUNTIME
  }

  enum Mode {
    PREDICTED,
    OBSERVED
  }

  enum VersionApplicability {
    APPLICABLE,
    NOT_APPLICABLE,
    UNKNOWN,
    NO_COMPONENT
  }

  enum Status {
    PASS,
    VIOLATION,
    UNKNOWN,
    NOT_APPLICABLE
  }

  record Match(
      String provider, String entry, Integer tier, String resolvedOwner, List<String> descriptors) {
    Match {
      optional(provider, "provider");
      optional(entry, "entry");
      optional(resolvedOwner, "resolvedOwner");
      if (tier == null || tier != 0 && tier < MultiReleaseEntryPath.MINIMUM_RELEASE) {
        throw new IllegalArgumentException("tier must be zero or at least 9");
      }
      descriptors = List.copyOf(Objects.requireNonNull(descriptors, "descriptors"));
      descriptors.forEach(
          value -> {
            required(value, "descriptor");
            if (!METHOD_DESCRIPTOR.matcher(value).matches()) {
              throw new IllegalArgumentException("Invalid method descriptor");
            }
          });
    }
  }

  ForbiddenCodeAssessment {
    required(cveId, "cveId");
    if (!CVE.matcher(cveId).matches()) {
      throw new IllegalArgumentException("Invalid cveId");
    }
    required(symbol, "symbol");
    final ForbiddenSymbol target = ForbiddenSymbol.parse(symbol);
    Objects.requireNonNull(componentKind, "componentKind");
    optional(componentIdentity, "componentIdentity");
    required(versionScope, "versionScope");
    MavenVersionRangeMatcher.validate(versionScope);
    optional(componentVersion, "componentVersion");
    if (targetRelease != null && targetRelease < 1) {
      throw new IllegalArgumentException("targetRelease must be positive");
    }
    Objects.requireNonNull(mode, "mode");
    Objects.requireNonNull(versionApplicability, "versionApplicability");
    Objects.requireNonNull(status, "status");
    required(evidenceKind, "evidenceKind");
    if (!EVIDENCE_KINDS.contains(evidenceKind)) {
      throw new IllegalArgumentException("Invalid evidenceKind");
    }
    optional(provider, "provider");
    matches = List.copyOf(Objects.requireNonNull(matches, "matches"));
    required(reason, "reason");
    required(provenance, "provenance");
    optional(sourceUrl, "sourceUrl");
    new AdvisoryProvenance(
        EvidenceOrigin.POM, provenance, sourceUrl == null ? null : URI.create(sourceUrl), null);
    if (status == Status.PASS && !complete) {
      throw new IllegalArgumentException("PASS requires complete evidence");
    }
    if ((status == Status.NOT_APPLICABLE)
        != (versionApplicability == VersionApplicability.NOT_APPLICABLE)) {
      throw new IllegalArgumentException(
          "NOT_APPLICABLE status disagrees with version applicability");
    }
    if (versionApplicability == VersionApplicability.NO_COMPONENT && componentVersion != null) {
      throw new IllegalArgumentException("NO_COMPONENT cannot have a component version");
    }
    if (versionApplicability == VersionApplicability.NO_COMPONENT && status != Status.PASS) {
      throw new IllegalArgumentException("NO_COMPONENT requires PASS");
    }
    final boolean directCall = DIRECT_RUNTIME_CALL.equals(evidenceKind);
    final boolean unverifiedDirectCall =
        directCall && versionApplicability == VersionApplicability.UNKNOWN;
    if (versionApplicability == VersionApplicability.UNKNOWN
        && status != Status.UNKNOWN
        && !unverifiedDirectCall) {
      throw new IllegalArgumentException("Unknown version applicability requires UNKNOWN");
    }
    if (status == Status.UNKNOWN && complete) {
      throw new IllegalArgumentException("UNKNOWN evidence cannot be complete");
    }
    if (status == Status.VIOLATION
        && (matches.isEmpty()
            || versionApplicability != VersionApplicability.APPLICABLE && !unverifiedDirectCall)) {
      throw new IllegalArgumentException("VIOLATION requires matches within the policy scope");
    }
    if (status != Status.VIOLATION && !matches.isEmpty()) {
      throw new IllegalArgumentException("Only VIOLATION may contain matches");
    }
    if (directCall) {
      if (componentKind != ComponentKind.JAVA_RUNTIME
          || status != Status.VIOLATION
          || target.method() == null
          || targetRelease == null
          || matches.stream().anyMatch(match -> !matchesInvocation(match, target, targetRelease))) {
        throw new IllegalArgumentException(
            "DIRECT_RUNTIME_CALL requires a runtime method violation and invocation evidence");
      }
      if (!unverifiedDirectCall
          && (componentIdentity == null || componentVersion == null || provider == null)) {
        throw new IllegalArgumentException(
            "Applicable runtime evidence requires a runtime identity");
      }
    } else if (componentKind == ComponentKind.JAVA_RUNTIME && status == Status.VIOLATION) {
      throw new IllegalArgumentException("Runtime violations require DIRECT_RUNTIME_CALL evidence");
    }
  }

  private static boolean matchesInvocation(
      final Match match, final ForbiddenSymbol target, final int targetRelease) {
    return match.provider() != null
        && match.entry() != null
        && match.entry().endsWith(".class")
        && matchesEntryTier(match.entry(), match.tier(), targetRelease)
        && match.resolvedOwner() != null
        && compatibleName(target.owner(), match.resolvedOwner())
        && !match.descriptors().isEmpty()
        && match.descriptors().stream()
            .allMatch(descriptor -> matchesArguments(target.parameters(), descriptor));
  }

  private static boolean matchesEntryTier(
      final String entry, final int tier, final int targetRelease) {
    if (tier == 0) {
      return !entry.startsWith(MultiReleaseEntryPath.PREFIX);
    }
    return tier <= targetRelease && entry.startsWith(MultiReleaseEntryPath.PREFIX + tier + "/");
  }

  private static boolean matchesArguments(final List<String> parameters, final String descriptor) {
    final Type[] arguments = Type.getArgumentTypes(descriptor);
    if (arguments.length != parameters.size()) {
      return false;
    }
    for (int index = 0; index < arguments.length; index++) {
      if (!compatibleName(parameters.get(index), arguments[index].getClassName())) {
        return false;
      }
    }
    return true;
  }

  // The scan verifies source member names. Replay has only binary names.
  private static boolean compatibleName(final String expected, final String binary) {
    if (expected.length() != binary.length()) {
      return false;
    }
    for (int index = 0; index < binary.length(); index++) {
      final char actual = binary.charAt(index);
      final char configured = expected.charAt(index);
      if (actual != configured && !(actual == '$' && configured == '.')) {
        return false;
      }
    }
    return true;
  }

  private static void required(final String value, final String field) {
    if (value == null || value.isBlank()) {
      throw new IllegalArgumentException(field + " must be nonblank");
    }
  }

  private static void optional(final String value, final String field) {
    if (value != null) {
      required(value, field);
    }
  }
}
