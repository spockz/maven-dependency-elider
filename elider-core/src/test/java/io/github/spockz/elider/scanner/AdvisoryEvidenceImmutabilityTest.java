/* WHY: Keeps deep immutability assertions separate from codec coverage. */

package io.github.spockz.elider.scanner;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;

import io.github.spockz.elider.model.AdvisoryProvenance;
import io.github.spockz.elider.model.AdvisoryScope;
import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.EvidenceOrigin;
import io.github.spockz.elider.model.OsvAdvisoryRecord;
import io.github.spockz.elider.model.OsvAffectedPackage;
import io.github.spockz.elider.model.StructuredSourceClassEvidence;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import org.junit.jupiter.api.Test;

/** Tests deep immutability of cached evidence model inputs and outputs. */
class AdvisoryEvidenceImmutabilityTest {
  /** Creates one isolated immutability test instance. */
  /* package */
  AdvisoryEvidenceImmutabilityTest() {
    // JUnit constructs one instance per test method.
  }

  /** Caller-owned collections cannot mutate constructed evidence. */
  @Test
  void freezesNestedCollectionsOnTypedRecordConstruction() {
    final String cveId = "CVE-2025-12345";
    final String file = "src/main/java/org/example/Resolved.java";
    final String routine = "decode";
    final Set<String> mutableAliases = new LinkedHashSet<>(Set.of(cveId));
    final Set<String> mutableFiles = new LinkedHashSet<>(Set.of(file));
    final Set<String> mutableRoutines = new LinkedHashSet<>(Set.of(routine));
    final Set<String> mutableFileClasses = new LinkedHashSet<>(Set.of("org.example.Resolved"));
    final Set<String> mutableRoutineClasses = new LinkedHashSet<>(Set.of("org.example.Decoder"));
    final Map<String, Set<String>> mutableFileAttribution = new ConcurrentHashMap<>();
    mutableFileAttribution.put(file, mutableFileClasses);
    final Map<String, Set<String>> mutableRoutineAttribution = new ConcurrentHashMap<>();
    mutableRoutineAttribution.put(routine, mutableRoutineClasses);
    final StructuredSourceClassEvidence structured =
        new StructuredSourceClassEvidence(
            scope(),
            new AdvisoryProvenance(EvidenceOrigin.CVE_LIST, cveId, null, "a".repeat(64)),
            "Example:library",
            mutableFiles,
            mutableRoutines,
            mutableFileAttribution,
            mutableRoutineAttribution);
    final OsvAdvisoryRecord record =
        new OsvAdvisoryRecord(
            "GHSA-owner",
            mutableAliases,
            List.of(
                new OsvAffectedPackage(
                    "Maven",
                    "org.example:library",
                    ArtifactCoordinate.of("org.example", "library", null),
                    List.of("1.0"),
                    List.of())),
            List.of(),
            List.of(structured));
    mutableAliases.clear();
    mutableFiles.clear();
    mutableRoutines.clear();
    mutableFileClasses.clear();
    mutableRoutineClasses.clear();
    mutableFileAttribution.clear();
    mutableRoutineAttribution.clear();

    assertAll(
        () -> assertThat(record.aliases()).containsExactly(cveId),
        () ->
            assertThatThrownBy(() -> record.aliases().add("CVE-2025-67890"))
                .isInstanceOf(UnsupportedOperationException.class),
        () ->
            assertThatThrownBy(() -> record.affectedPackages().getFirst().versions().add("2.0"))
                .isInstanceOf(UnsupportedOperationException.class),
        () -> assertThat(structured.programFiles()).containsExactly(file),
        () -> assertThat(structured.programRoutines()).containsExactly(routine),
        () ->
            assertThat(structured.fileClassAttribution())
                .containsEntry(file, Set.of("org.example.Resolved")),
        () ->
            assertThat(structured.routineClassAttribution())
                .containsEntry(routine, Set.of("org.example.Decoder")),
        () ->
            assertThatThrownBy(() -> structured.programFiles().add("src/extra/Other.java"))
                .isInstanceOf(UnsupportedOperationException.class),
        () ->
            assertThatThrownBy(() -> structured.fileClassAttribution().put("Other.java", Set.of()))
                .isInstanceOf(UnsupportedOperationException.class),
        () ->
            assertThatThrownBy(
                    () -> structured.fileClassAttribution().get(file).add("org.example.Other"))
                .isInstanceOf(UnsupportedOperationException.class));
  }

  private static AdvisoryScope scope() {
    return new AdvisoryScope(
        "CVE-2025-12345",
        ArtifactCoordinate.of("org.example", "library", null),
        "[1.0,2.0)",
        "Maven",
        "org.example:library");
  }
}
