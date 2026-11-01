/* WHY: Guards the raw version and exact CNA-entry gates for SourceFile review candidates. */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

import io.github.spockz.elider.model.AdvisoryProvenance;
import io.github.spockz.elider.model.AdvisoryScope;
import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.CveAffectedEntryContext;
import io.github.spockz.elider.model.CveSourceRecordMetadata;
import io.github.spockz.elider.model.CveVersionClaim;
import io.github.spockz.elider.model.EvidenceOrigin;
import io.github.spockz.elider.model.OsvAdvisoryRecord;
import io.github.spockz.elider.model.OsvAffectedPackage;
import io.github.spockz.elider.model.OsvAffectedRange;
import io.github.spockz.elider.model.StructuredSourceClassEvidence;
import io.github.spockz.elider.scanner.JarSourceFileIndex;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;

/** Tests exact-version gates without cache or proof dispatch. */
@SuppressWarnings("PMD.AtLeastOneConstructor")
class CorroboratedSourceCandidateMatcherTest {
  /** Owner CVE shared by OSV and CNA test evidence. */
  private static final String CVE_ID = "CVE-2025-12345";

  /** Maven package name used to bind the CNA entry. */
  private static final String PACKAGE_NAME = "org.example:demo";

  /** Name of the tested Maven artifact. */
  private static final String ARTIFACT_NAME = "demo";

  /** Exact CNA state required for a source candidate. */
  private static final String AFFECTED = "affected";

  /** Conflicting CNA state that must suppress the candidate. */
  private static final String UNAFFECTED = "unaffected";

  /** Default status used when no CNA version claim matches. */
  private static final String DEFAULT_STATUS = "affected";

  /** OSV version scope used by the matching scenarios. */
  private static final String OSV_RANGE = "[1.0,2.0)";

  /** Concrete version shared by the exact CNA claim and candidate. */
  private static final String VERSION = "1.0";

  /** Concrete Maven artifact analyzed by the matcher. */
  private static final ArtifactCoordinate COMPONENT =
      ArtifactCoordinate.of("org.example", ARTIFACT_NAME, VERSION);

  /** Source path attached to the CNA affected entry. */
  private static final String SOURCE_FILE = "src/main/java/org/example/Outer.java";

  /** Temporary destination for the generated class archive. */
  @TempDir private Path tempDir;

  @Test
  void requiresUnambiguousRawOsvAndCnaApplicability() throws IOException {
    final Path archive = writeArchive();
    final JarSourceFileIndex sourceIndex = JarSourceFileIndex.read(archive);

    assertAll(
        "only agreeing supported raw OSV and CNA claims produce a source review candidate",
        () ->
            assertThat(candidates(record(OSV_RANGE, "0.9", AFFECTED, null), sourceIndex)).isEmpty(),
        () ->
            assertThat(
                    candidates(record(OSV_RANGE, VERSION, UNAFFECTED, DEFAULT_STATUS), sourceIndex))
                .isEmpty(),
        () -> assertThat(candidates(record(OSV_RANGE, null, null, null), sourceIndex)).isEmpty(),
        () ->
            assertThat(
                    candidates(record("[2.0,3.0)", VERSION, AFFECTED, DEFAULT_STATUS), sourceIndex))
                .isEmpty(),
        () ->
            assertThat(
                    candidates(
                        recordWithClaims(
                            OSV_RANGE,
                            null,
                            List.of(
                                new CveVersionClaim(
                                    VERSION, AFFECTED, "maven", "1.1", null, List.of()))),
                        sourceIndex))
                .hasSize(1),
        () ->
            assertThat(
                    candidates(
                        recordWithClaims(
                            OSV_RANGE,
                            DEFAULT_STATUS,
                            List.of(
                                new CveVersionClaim(VERSION, AFFECTED, null, null, null, List.of()),
                                new CveVersionClaim(
                                    "0.9", AFFECTED, null, "1.1", null, List.of()))),
                        sourceIndex))
                .isEmpty(),
        () ->
            assertThat(
                    candidates(
                        recordWithClaims(
                            OSV_RANGE,
                            DEFAULT_STATUS,
                            List.of(
                                new CveVersionClaim(
                                    VERSION,
                                    AFFECTED,
                                    null,
                                    null,
                                    null,
                                    List.of(Map.of("at", "1.1"))))),
                        sourceIndex))
                .isEmpty(),
        () ->
            assertThat(
                    candidates(
                        recordWithClaims(
                            OSV_RANGE,
                            DEFAULT_STATUS,
                            List.of(
                                new CveVersionClaim(VERSION, AFFECTED, null, null, null, List.of()),
                                new CveVersionClaim(
                                    VERSION, UNAFFECTED, null, null, null, List.of()))),
                        sourceIndex))
                .isEmpty(),
        () ->
            assertThat(candidates(record(OSV_RANGE, VERSION, AFFECTED, "unaffected"), sourceIndex))
                .hasSize(1),
        () ->
            assertThat(candidates(record(OSV_RANGE, null, null, DEFAULT_STATUS), sourceIndex))
                .hasSize(1),
        () ->
            assertThat(
                    candidates(
                        withDuplicateCnaProduct(record(OSV_RANGE, VERSION, AFFECTED, null)),
                        sourceIndex))
                .isEmpty(),
        () ->
            assertThat(
                    candidates(
                        withDuplicateOsvPackage(record(OSV_RANGE, VERSION, AFFECTED, null)),
                        sourceIndex))
                .isEmpty());
  }

  private static OsvAdvisoryRecord withDuplicateCnaProduct(final OsvAdvisoryRecord source) {
    final CveAffectedEntryContext original = source.cnaAffectedEntries().getFirst();
    final CveAffectedEntryContext duplicate =
        new CveAffectedEntryContext(
            "containers.cna.affected[1]",
            original.sourceRecord(),
            original.vendor(),
            original.product(),
            original.packageUrl(),
            original.collectionUrl(),
            original.packageName(),
            original.defaultStatus(),
            original.versions(),
            original.programFiles(),
            original.programRoutines());
    return new OsvAdvisoryRecord(
        source.osvId(),
        source.modified(),
        source.aliases(),
        source.affectedPackages(),
        List.of(original, duplicate),
        source.evidence());
  }

  private static OsvAdvisoryRecord withDuplicateOsvPackage(final OsvAdvisoryRecord source) {
    final OsvAffectedPackage affectedPackage = source.affectedPackages().getFirst();
    return new OsvAdvisoryRecord(
        source.osvId(),
        source.modified(),
        source.aliases(),
        List.of(affectedPackage, affectedPackage),
        source.cnaAffectedEntries(),
        source.evidence());
  }

  private List<io.github.spockz.elider.model.CorroboratedSourceClassCandidate> candidates(
      final OsvAdvisoryRecord record, final JarSourceFileIndex index) {
    final StructuredSourceClassEvidence evidence =
        (StructuredSourceClassEvidence) record.evidence().getFirst();
    return CorroboratedSourceCandidateMatcher.candidates(record, evidence, COMPONENT, index, false);
  }

  private OsvAdvisoryRecord record(
      final String osvRange,
      final String cnaVersion,
      final String cnaStatus,
      final String defaultStatus) {
    final List<CveVersionClaim> versions =
        cnaVersion == null
            ? List.of()
            : List.of(new CveVersionClaim(cnaVersion, cnaStatus, null, null, null, List.of()));
    return recordWithClaims(osvRange, defaultStatus, versions);
  }

  private OsvAdvisoryRecord recordWithClaims(
      final String osvRange, final String defaultStatus, final List<CveVersionClaim> versions) {
    final AdvisoryScope scope =
        new AdvisoryScope(
            CVE_ID,
            ArtifactCoordinate.of("org.example", ARTIFACT_NAME, null),
            osvRange,
            "Maven",
            PACKAGE_NAME);
    final CveAffectedEntryContext entry =
        new CveAffectedEntryContext(
            "containers.cna.affected[0]",
            new CveSourceRecordMetadata(
                true, true, true, CVE_ID, true, "PUBLISHED", "a".repeat(64)),
            "Example",
            ARTIFACT_NAME,
            "pkg:maven/org.example/demo",
            null,
            null,
            defaultStatus,
            versions,
            Set.of(SOURCE_FILE),
            Set.of());
    final StructuredSourceClassEvidence evidence =
        new StructuredSourceClassEvidence(
            scope,
            new AdvisoryProvenance(EvidenceOrigin.CVE_LIST, CVE_ID, null, "a".repeat(64)),
            entry.entryIdentity(),
            "Example:" + ARTIFACT_NAME,
            entry.programFiles(),
            entry.programRoutines(),
            Map.of(SOURCE_FILE, Set.of()),
            Map.of());
    final OsvAffectedPackage affectedPackage =
        new OsvAffectedPackage(
            "Maven",
            PACKAGE_NAME,
            ArtifactCoordinate.of("org.example", ARTIFACT_NAME, null),
            List.of(),
            List.of(osvRange(osvRange)));
    return new OsvAdvisoryRecord(
        "GHSA-candidate",
        "2026-10-31T00:00:00Z",
        Set.of(CVE_ID),
        List.of(affectedPackage),
        List.of(entry),
        List.of(evidence));
  }

  private static OsvAffectedRange osvRange(final String specification) {
    final String bounds = specification.substring(1, specification.length() - 1);
    final int separator = bounds.indexOf(',');
    return new OsvAffectedRange(
        "ECOSYSTEM",
        null,
        List.of(
            Map.of("introduced", bounds.substring(0, separator)),
            Map.of("fixed", bounds.substring(separator + 1))));
  }

  private Path writeArchive() throws IOException {
    final Path archive = tempDir.resolve("candidate.jar");
    final ClassWriter writer = new ClassWriter(0);
    writer.visit(
        Opcodes.V17, Opcodes.ACC_PUBLIC, "org/example/Outer", null, "java/lang/Object", null);
    writer.visitSource("Outer.java", null);
    writer.visitEnd();
    try (ZipOutputStream zip = new ZipOutputStream(Files.newOutputStream(archive))) {
      zip.putNextEntry(new ZipEntry("org/example/Outer.class"));
      zip.write(writer.toByteArray());
      zip.closeEntry();
    }
    return archive;
  }
}
