/* WHY: Validates Snyk package pages before projecting vulnerability contributions. */

package io.github.spockz.elider.advisory;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.StreamReadFeature;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.spockz.elider.model.AdvisoryProvenance;
import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.AssessmentIntent;
import io.github.spockz.elider.model.EvidenceOrigin;
import io.github.spockz.elider.model.FieldValue;
import io.github.spockz.elider.model.MergePriority;
import io.github.spockz.elider.model.VersionCoverageClaim;
import io.github.spockz.elider.model.VulnerabilityFindingContribution;
import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Pattern;

@SuppressWarnings({"PMD.CommentRequired", "PMD.GodClass", "PMD.TooManyMethods"})
final class SnykPackageIssuesResponseReader {
  private static final String PACKAGE_VULNERABILITY = "package_vulnerability";
  private static final String CVE_SOURCE = "CVE";
  private static final Pattern CVE_ID = Pattern.compile("CVE-[0-9]{4}-[0-9]{4,}");

  private final ObjectMapper mapper =
      new ObjectMapper(
              JsonFactory.builder().enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION).build())
          .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);

  /** Creates a strict response reader. */
  /* package */ SnykPackageIssuesResponseReader() {
    super();
  }

  // Each response is read and accumulated sequentially within its calling query.
  @SuppressWarnings("PMD.UseConcurrentHashMap")
  /* package */ Page read(final byte[] bytes, final ArtifactCoordinate coordinate)
      throws IOException {
    final JsonNode page = mapper.readTree(bytes);
    validatePackageMetadata(page, coordinate);
    final JsonNode rows = page.get("data");
    if (rows == null || !rows.isArray()) {
      throw new IllegalArgumentException("response did not contain an issue list");
    }
    final Map<String, VulnerabilityFindingContribution> contributions = new LinkedHashMap<>();
    final List<String> diagnostics = new ArrayList<>();
    collectRows(rows, coordinate, contributions, diagnostics);
    final PaginationLink pagination = paginationLink(page.get("links"));
    return new Page(
        List.copyOf(contributions.values()),
        List.copyOf(diagnostics),
        pagination.next(),
        pagination.invalid(),
        rows.size());
  }

  private static void collectRows(
      final JsonNode rows,
      final ArtifactCoordinate coordinate,
      final Map<String, VulnerabilityFindingContribution> contributions,
      final List<String> diagnostics) {
    int rowIndex = 0;
    for (final JsonNode row : rows) {
      rowIndex++;
      try {
        final VulnerabilityFindingContribution contribution = contributionFor(row, coordinate);
        contributions.merge(
            contribution.vulnerabilityId(),
            contribution,
            SnykPackageIssuesResponseReader::mergeDuplicate);
      } catch (final UnsupportedIssueTypeException exception) {
        diagnostics.add("Snyk issue row " + rowIndex + " had an unsupported issue type");
      } catch (final IllegalArgumentException exception) {
        diagnostics.add("Snyk issue row " + rowIndex + " was malformed");
      }
    }
  }

  private static PaginationLink paginationLink(final JsonNode links) {
    if (links == null) {
      return PaginationLink.none();
    }
    if (!links.isObject()) {
      return PaginationLink.invalidLink();
    }
    if (!links.has("next") || links.get("next").isNull()) {
      return PaginationLink.none();
    }
    final JsonNode next = links.get("next");
    return next.isTextual() && !next.asText().isBlank()
        ? new PaginationLink(next.asText(), false)
        : PaginationLink.invalidLink();
  }

  private static void validatePackageMetadata(
      final JsonNode page, final ArtifactCoordinate coordinate) {
    if (page == null || !page.isObject()) {
      throw new IllegalArgumentException("response is not an object");
    }
    final JsonNode packageMetadata = page.path("meta").path("package");
    if (!packageMetadata.isObject()) {
      throw new IllegalArgumentException("response package metadata is missing");
    }
    validatePackageName(packageMetadata, coordinate);
    validatePackagePurl(packageMetadata, coordinate);
  }

  private static void validatePackageName(
      final JsonNode packageMetadata, final ArtifactCoordinate coordinate) {
    if (!coordinate.artifactId().equals(text(packageMetadata.get("name")))
        || !"maven".equalsIgnoreCase(text(packageMetadata.get("type")))) {
      throw new IllegalArgumentException("response package name does not match request");
    }
  }

  private static void validatePackagePurl(
      final JsonNode packageMetadata, final ArtifactCoordinate coordinate) {
    final String expectedPurl =
        "pkg:maven/"
            + coordinate.groupId()
            + "/"
            + coordinate.artifactId()
            + "@"
            + coordinate.version();
    if (!expectedPurl.equals(text(packageMetadata.get("url")))
        || !coordinate.version().equals(text(packageMetadata.get("version")))) {
      throw new IllegalArgumentException("response package version does not match request");
    }
  }

  private static VulnerabilityFindingContribution contributionFor(
      final JsonNode row, final ArtifactCoordinate coordinate) {
    validateIssueEnvelope(row);
    final String issueId = text(row.get("id"));
    final JsonNode attributes = row.get("attributes");
    validateIssueAttributes(issueId, attributes);
    if (!PACKAGE_VULNERABILITY.equals(text(attributes.get("type")))) {
      throw new UnsupportedIssueTypeException();
    }
    return contribution(issueId, cveAliases(attributes.get("problems")), coordinate);
  }

  private static void validateIssueEnvelope(final JsonNode row) {
    if (row == null || !row.isObject() || !"issue".equals(text(row.get("type")))) {
      throw new IllegalArgumentException("issue row is invalid");
    }
  }

  private static void validateIssueAttributes(final String issueId, final JsonNode attributes) {
    if (issueId == null
        || !issueId.startsWith("SNYK-")
        || attributes == null
        || !attributes.isObject()) {
      throw new IllegalArgumentException("issue row identity is invalid");
    }
  }

  private static VulnerabilityFindingContribution contribution(
      final String issueId, final Set<String> aliases, final ArtifactCoordinate coordinate) {
    final AdvisoryProvenance provenance = provenance(issueId);
    return new VulnerabilityFindingContribution(
        issueId,
        aliases,
        coordinate.groupId(),
        coordinate.artifactId(),
        coordinate.type(),
        coordinate.classifier(),
        List.of(exactVersionClaim(issueId, coordinate.version())),
        FieldValue.omitted(),
        FieldValue.omitted(),
        MergePriority.AUTOMATIC,
        AssessmentIntent.AUTO_VERIFY,
        "snyk:" + issueId,
        Set.of(provenance));
  }

  private static AdvisoryProvenance provenance(final String issueId) {
    final URI advisoryUrl =
        URI.create(
            "https://security.snyk.io/vuln/"
                + URLEncoder.encode(issueId, StandardCharsets.UTF_8).replace("+", "%20"));
    return new AdvisoryProvenance(EvidenceOrigin.SNYK, issueId, advisoryUrl, null);
  }

  private static VersionCoverageClaim exactVersionClaim(
      final String issueId, final String exactVersion) {
    final String pointRange = "[" + exactVersion + "]";
    try {
      return VersionCoverageClaim.affected(pointRange);
    } catch (final IllegalArgumentException exception) {
      return VersionCoverageClaim.unresolvedAffected(
          "snyk:" + issueId + ":" + exactVersion,
          "Snyk exact package version cannot be represented as a Maven singleton range");
    }
  }

  private static Set<String> cveAliases(final JsonNode problems) {
    if (problems == null) {
      return Set.of();
    }
    if (!problems.isArray()) {
      throw new IllegalArgumentException("issue problems are invalid");
    }
    final Set<String> aliases = new TreeSet<>();
    for (final JsonNode problem : problems) {
      final String cveId = cveAlias(problem);
      if (cveId != null) {
        aliases.add(cveId);
      }
    }
    return aliases;
  }

  private static String cveAlias(final JsonNode problem) {
    if (problem == null || !problem.isObject()) {
      throw new IllegalArgumentException("issue problem is invalid");
    }
    if (!CVE_SOURCE.equalsIgnoreCase(text(problem.get("source")))) {
      return null;
    }
    final String cveId = text(problem.get("id"));
    if (cveId == null || !CVE_ID.matcher(cveId).matches()) {
      throw new IllegalArgumentException("CVE identifier is invalid");
    }
    return cveId;
  }

  /* package */ static VulnerabilityFindingContribution mergeDuplicate(
      final VulnerabilityFindingContribution first, final VulnerabilityFindingContribution next) {
    final Set<String> aliases = new TreeSet<>(first.aliases());
    aliases.addAll(next.aliases());
    return new VulnerabilityFindingContribution(
        first.vulnerabilityId(),
        aliases,
        first.groupId(),
        first.artifactId(),
        first.type(),
        first.classifier(),
        first.versionClaims(),
        first.codeGroup(),
        first.prerequisiteGroup(),
        first.priority(),
        first.intent(),
        first.provenance(),
        first.sourceProvenance());
  }

  private static String text(final JsonNode node) {
    return node != null && node.isTextual() && !node.asText().isBlank() ? node.asText() : null;
  }

  /* package */ record Page(
      List<VulnerabilityFindingContribution> contributions,
      List<String> diagnostics,
      String nextLink,
      boolean invalidPagination,
      int rowsReturned) {}

  private record PaginationLink(String next, boolean invalid) {
    private static PaginationLink none() {
      return new PaginationLink(null, false);
    }

    private static PaginationLink invalidLink() {
      return new PaginationLink(null, true);
    }
  }

  private static final class UnsupportedIssueTypeException extends IllegalArgumentException {
    private static final long serialVersionUID = 1L;
  }
}
