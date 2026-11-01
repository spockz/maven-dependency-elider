/* WHY: Proves proof inputs are rebound to the live CVE record and current OSV owner. */

package io.github.spockz.elider.model;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.spockz.elider.scanner.VulnerabilityCacheEnvelopeWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Exercises live source and cache-owner binding without granting proof authority. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class LiveStructuredSourceValidatorTest {
  /** CVE source fixture identifier. */
  static final String CVE_ID = "CVE-2025-12345";

  /** OSV owner fixture identifier. */
  private static final String OSV_ID = "GHSA-proof-owner";

  /** CNA locator fixture value. */
  private static final String ENTRY_ID = "containers.cna.affected[0]";

  /** Relative source path fixture value. */
  private static final String SOURCE_FILE = "src/main/java/org/example/Library.java";

  /** Expected top-level binary name. */
  private static final String CLASS_NAME = "org.example.Library";

  /** Fixture artifact identifier. */
  static final String ARTIFACT_ID = "library";

  /** Maven group used by the live-source fixtures. */
  static final String GROUP_ID = "org.example";

  /** Concrete fixture version. */
  private static final String VERSION = "1.0";

  /** Positive CNA version status. */
  static final String AFFECTED_STATUS = "affected";

  /** Per-test isolated filesystem root. */
  @TempDir private Path tempDir;

  /** Creates a JUnit test instance. */
  LiveStructuredSourceValidatorTest() {
    // JUnit creates one test instance for each scenario.
  }

  @Test
  void acceptsOnlyCurrentPublishedCnaBytesBoundToTheExactOwnerAndCandidate() throws Exception {
    final Fixture fixture = fixture(tempDir, cveJson(AFFECTED_STATUS, false));

    final LiveStructuredSourceValidator.ObservedInputs observed =
        LiveStructuredSourceValidator.observe(fixture.request());

    assertThat(
            List.of(
                observed.candidate(),
                observed.currentCveRecord().sourceRecordSha256(),
                observed.cnaEntry().entryIdentity(),
                observed.osvPackage().packageName()))
        .containsExactly(
            fixture.candidate(), fixture.digest(), ENTRY_ID, GROUP_ID + ":" + ARTIFACT_ID);
  }

  @Test
  void rejectsChangedCurrentCnaBytesEvenWhenTheTypedOwnerStillMatchesOldBytes() throws Exception {
    final Fixture fixture = fixture(tempDir, cveJson(AFFECTED_STATUS, false));
    Files.writeString(fixture.sourcePath(), cveJson("unaffected", false));

    assertThatThrownBy(() -> LiveStructuredSourceValidator.observe(fixture.request()))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("Current CVE source bytes");
  }

  @Test
  void rejectsDuplicateExactCnaProductClaims() throws Exception {
    final String duplicateProduct = cveJson(AFFECTED_STATUS, true);
    final Fixture fixture = fixture(tempDir, duplicateProduct);

    assertThatThrownBy(() -> LiveStructuredSourceValidator.observe(fixture.request()))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("unique matching affected entry");
  }

  @Test
  void rejectsAnIncompatibleProducerInTheTypedAdvisoryIndex() throws Exception {
    final Fixture fixture = fixture(tempDir, cveJson(AFFECTED_STATUS, false));
    final StructuredSourceProofRequest mismatchedProducer =
        fixture.withProducer(
            new CacheProducerIdentity("io.github.spockz", "elider-plugin", "2.0", null));
    assertThatThrownBy(() -> LiveStructuredSourceValidator.observe(mismatchedProducer))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("producer identity does not match");
  }

  @Test
  void rejectsMissingTypedAdvisoryIndex() throws Exception {
    final Fixture fixture = fixture(tempDir, cveJson(AFFECTED_STATUS, false));
    final StructuredSourceProofRequest missingIndex =
        fixture.withIndex(tempDir.resolve("missing-index.json"));

    assertThatThrownBy(() -> LiveStructuredSourceValidator.observe(missingIndex))
        .isInstanceOf(IOException.class);
  }

  static Fixture fixture(final Path tempDir, final String sourceJson)
      throws IOException, NoSuchAlgorithmException {
    return fixture(tempDir, sourceJson, null, "Maven");
  }

  static Fixture fixture(
      final Path tempDir,
      final String sourceJson,
      final String scopeVersion,
      final String ecosystem)
      throws IOException, NoSuchAlgorithmException {
    final Path cveListRoot = tempDir.resolve("cvelistV5");
    final Path sourcePath = cveListRoot.resolve("cves/2025/12xxx/").resolve(CVE_ID + ".json");
    Files.createDirectories(sourcePath.getParent());
    Files.writeString(sourcePath, sourceJson);
    final byte[] raw = Files.readAllBytes(sourcePath);
    final String digest =
        HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw));
    final CveSourceRecordMetadata sourceMetadata =
        new CveSourceRecordMetadata(true, true, true, CVE_ID, true, "PUBLISHED", digest);
    final CveAffectedEntryContext entry =
        new CveAffectedEntryContext(
            ENTRY_ID,
            sourceMetadata,
            "Example",
            ARTIFACT_ID,
            "pkg:maven/" + GROUP_ID + "/library",
            null,
            null,
            null,
            List.of(new CveVersionClaim(VERSION, AFFECTED_STATUS, "maven", null, null, List.of())),
            Set.of(SOURCE_FILE),
            Set.of());
    final ArtifactCoordinate osvCoordinate = ArtifactCoordinate.of(GROUP_ID, ARTIFACT_ID, null);
    final OsvAffectedPackage affectedPackage =
        new OsvAffectedPackage(
            ecosystem, GROUP_ID + ":" + ARTIFACT_ID, osvCoordinate, List.of(VERSION), List.of());
    final AdvisoryScope scope =
        new AdvisoryScope(
            CVE_ID,
            ArtifactCoordinate.of(GROUP_ID, ARTIFACT_ID, scopeVersion),
            "[" + VERSION + "]",
            ecosystem,
            GROUP_ID + ":" + ARTIFACT_ID);
    final StructuredSourceClassEvidence evidence =
        new StructuredSourceClassEvidence(
            scope,
            new AdvisoryProvenance(EvidenceOrigin.CVE_LIST, CVE_ID, null, digest),
            ENTRY_ID,
            "Example:library",
            Set.of(SOURCE_FILE),
            Set.of(),
            Map.of(SOURCE_FILE, Set.of(CLASS_NAME)),
            Map.of());
    final OsvAdvisoryRecord owner =
        new OsvAdvisoryRecord(
            OSV_ID,
            "2026-10-31T00:00:00Z",
            Set.of(CVE_ID),
            List.of(affectedPackage),
            List.of(entry),
            List.of(evidence));
    final CacheProducerIdentity producer =
        new CacheProducerIdentity("io.github.spockz", "elider-plugin", VERSION, null);
    final Path advisoryIndex = tempDir.resolve("index.json");
    Files.write(
        advisoryIndex, new VulnerabilityCacheEnvelopeWriter().encode(producer, List.of(owner)));
    final ArtifactCoordinate candidate = ArtifactCoordinate.of(GROUP_ID, ARTIFACT_ID, VERSION);
    final StructuredSourceProofRequest request =
        new StructuredSourceProofRequest(
            OSV_ID,
            evidence,
            candidate,
            cveListRoot,
            advisoryIndex,
            producer,
            tempDir.resolve(ARTIFACT_ID + "-" + VERSION + "-sources.jar"),
            new ArtifactCoordinate(GROUP_ID, ARTIFACT_ID, VERSION, "jar", "sources", "compile"),
            "local repository",
            false);
    return new Fixture(sourcePath, advisoryIndex, digest, candidate, request);
  }

  static String cveJson(final String status, final boolean duplicateProduct) {
    final ObjectMapper mapper = new ObjectMapper();
    final ObjectNode root = mapper.createObjectNode();
    root.putObject("cveMetadata").put("cveId", CVE_ID).put("state", "PUBLISHED");
    final com.fasterxml.jackson.databind.node.ArrayNode affected =
        root.putObject("containers").putObject("cna").putArray("affected");
    addAffectedEntry(affected.addObject(), status);
    if (duplicateProduct) {
      addAffectedEntry(affected.addObject(), status);
    }
    return root.toString();
  }

  private static void addAffectedEntry(final ObjectNode entry, final String status) {
    entry
        .put("vendor", "Example")
        .put("product", ARTIFACT_ID)
        .put("packageURL", "pkg:maven/" + GROUP_ID + "/" + ARTIFACT_ID);
    entry
        .putArray("versions")
        .addObject()
        .put("version", VERSION)
        .put("status", status)
        .put("versionType", "maven");
    entry.putArray("programFiles").add(SOURCE_FILE);
  }

  record Fixture(
      Path sourcePath,
      Path advisoryIndex,
      String digest,
      ArtifactCoordinate candidate,
      StructuredSourceProofRequest request) {
    private StructuredSourceProofRequest withProducer(final CacheProducerIdentity producer) {
      return new StructuredSourceProofRequest(
          request.osvId(),
          request.sourceEvidence(),
          request.candidate(),
          request.cveListGitDir(),
          request.advisoryIndex(),
          producer,
          request.sourcesJar(),
          request.sourcesCoordinate(),
          request.sourceRepositoryProvenance(),
          request.conventionalLayoutAssumed());
    }

    private StructuredSourceProofRequest withIndex(final Path index) {
      return new StructuredSourceProofRequest(
          request.osvId(),
          request.sourceEvidence(),
          request.candidate(),
          request.cveListGitDir(),
          index,
          request.expectedProducer(),
          request.sourcesJar(),
          request.sourcesCoordinate(),
          request.sourceRepositoryProvenance(),
          request.conventionalLayoutAssumed());
    }
  }
}
