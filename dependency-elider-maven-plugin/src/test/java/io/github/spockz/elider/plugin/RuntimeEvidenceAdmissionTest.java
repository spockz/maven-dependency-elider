/* WHY: Pins per-input runtime-evidence admission before Maven planning can publish results. */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIOException;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertFalse;

import io.github.spockz.elider.model.TraceData;
import io.github.spockz.elider.trace.CompositeTraceEvidence;
import io.github.spockz.elider.trace.TraceEvidenceKind;
import io.github.spockz.elider.trimmer.ClosureQueryPolicy;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;

/** Exercises normalized evidence admission and per-file relevance. */
@SuppressWarnings("PMD.AtLeastOneConstructor")
final class RuntimeEvidenceAdmissionTest {
  /** Canonical class name shared by evidence and inventory fixtures. */
  private static final String ENTRY = "fixture.Entry";

  @Test
  void admittedBoundaryCombinesObservedExplicitAndActiveDynamicRoots() throws Exception {
    final CompositeTraceEvidence evidence =
        evidence(
            input("class-load.log", TraceEvidenceKind.CLASS_LOAD_LOG, "fixture/Entry"),
            input("coverage.exec", TraceEvidenceKind.JACOCO_EXECUTION, "fixture.Dependency"));

    final RuntimeEvidencePolicy policy =
        RuntimeEvidenceAdmission.admit(
            evidence,
            true,
            Set.of(ENTRY, "fixture/Dependency", "fixture.Unrelated"),
            Set.of("fixture/Explicit"),
            Set.of("fixture.Dynamic"));

    assertAll(
        "Admitted closed-world boundary combines observed, explicit, and active dynamic roots",
        () ->
            assertThat(policy.observedClasses())
                .containsExactlyInAnyOrder(ENTRY, "fixture.Dependency"),
        () ->
            assertThat(policy.allowedClasses())
                .containsExactlyInAnyOrder(
                    ENTRY, "fixture.Dependency", "fixture.Explicit", "fixture.Dynamic"),
        () ->
            assertThat(policy.evidenceKinds())
                .containsExactlyInAnyOrder(
                    TraceEvidenceKind.CLASS_LOAD_LOG, TraceEvidenceKind.JACOCO_EXECUTION));
  }

  @Test
  void preservesJfrKindAndRejectsEmptyEvidenceInClosedWorldMode() throws Exception {
    final CompositeTraceEvidence jfrEvidence =
        evidence(input("recording.jfr", TraceEvidenceKind.JFR_CLASS_LOAD, ENTRY));
    final RuntimeEvidencePolicy admitted =
        RuntimeEvidenceAdmission.admit(jfrEvidence, true, Set.of(ENTRY), Set.of(), Set.of());

    assertAll(
        "JFR kind is preserved and empty closed-world evidence is rejected",
        () ->
            assertThat(admitted.evidenceKinds()).containsExactly(TraceEvidenceKind.JFR_CLASS_LOAD),
        () ->
            assertThatIOException()
                .isThrownBy(
                    () ->
                        RuntimeEvidenceAdmission.admit(
                            new CompositeTraceEvidence(TraceData.empty(), List.of()),
                            true,
                            Set.of(ENTRY),
                            Set.of(),
                            Set.of())));
  }

  @Test
  void eachInputMustMatchApplicationOrDependencyInventoryIndependently() {
    final CompositeTraceEvidence evidence =
        evidence(
            input("valid.log", TraceEvidenceKind.CLASS_LOAD_LOG, ENTRY),
            input("jdk-only.lst", TraceEvidenceKind.CDS_CLASS_LIST, "java.lang.String"));

    assertThatIOException()
        .isThrownBy(
            () ->
                RuntimeEvidenceAdmission.admit(
                    evidence,
                    true,
                    Set.of(ENTRY, "fixture/Dependency"),
                    Set.of("fixture.MetadataRoot"),
                    Set.of("fixture.DynamicRoot")))
        .withMessageContaining("jdk-only.lst")
        .withMessageContaining("irrelevant");
  }

  @Test
  void graalConfigurationCannotServeAsClosedWorldRuntimeEvidence() {
    final CompositeTraceEvidence evidence =
        evidence(input("reflect-config.json", TraceEvidenceKind.GRAAL_CONFIGURATION, ENTRY));

    assertThatIOException()
        .isThrownBy(
            () ->
                RuntimeEvidenceAdmission.admit(
                    evidence, true, Set.of("fixture.Entry"), Set.of(), Set.of()))
        .withMessageContaining("reflect-config.json")
        .withMessageContaining("runtime class evidence");
  }

  @Test
  void conservativeModeRemainsUnboundedEvenWhenEvidenceIsAvailable() throws Exception {
    final CompositeTraceEvidence evidence =
        evidence(input("classes.log", TraceEvidenceKind.CLASS_LOAD_LOG, "fixture.Entry"));

    final RuntimeEvidencePolicy policy =
        RuntimeEvidenceAdmission.admit(evidence, false, Set.of(), Set.of(), Set.of());
    final boolean closedWorld = policy.closedWorld();
    final ClosureQueryPolicy queryPolicy = policy.closureQueryPolicy();

    assertAll(
        "Conservative mode remains unbounded even when trace evidence is present",
        () -> assertFalse(closedWorld, "conservative admission must not enable closed-world mode"),
        () -> assertThat(queryPolicy).isEqualTo(ClosureQueryPolicy.conservative()));
  }

  private static CompositeTraceEvidence evidence(final CompositeTraceEvidence.Input... inputs) {
    final List<CompositeTraceEvidence.Input> values = List.of(inputs);
    TraceData observations = TraceData.empty();
    for (final CompositeTraceEvidence.Input input : values) {
      observations = observations.merge(input.observations());
    }
    return new CompositeTraceEvidence(observations, values);
  }

  private static CompositeTraceEvidence.Input input(
      final String path, final TraceEvidenceKind kind, final String... classes) {
    return new CompositeTraceEvidence.Input(Path.of(path), kind, TraceData.of(Set.of(classes)));
  }
}
