// WHY: Protects persisted forbidden-code observations from loss and coercion during report replay.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.util.List;
import org.junit.jupiter.api.Test;

@SuppressWarnings({
  "PMD.CommentRequired",
  "PMD.AtLeastOneConstructor",
  "PMD.AvoidDuplicateLiterals"
})
final class ForbiddenCodeAssessmentCodecTest {
  @Test
  void roundTripsAndRejectsMalformedObservations() throws Exception {
    final ForbiddenCodeAssessment assessment =
        new ForbiddenCodeAssessment(
            "CVE-2026-12345",
            "example.Parser#parse(byte[])",
            ForbiddenCodeAssessment.ComponentKind.MAVEN_ARTIFACT,
            "example:lib:jar:1",
            "[1]",
            "1",
            21,
            true,
            ForbiddenCodeAssessment.VersionApplicability.APPLICABLE,
            ForbiddenCodeAssessment.Mode.OBSERVED,
            ForbiddenCodeAssessment.Status.VIOLATION,
            "PHYSICAL_DECLARATIONS",
            "/tmp/lib.jar",
            List.of(
                new ForbiddenCodeAssessment.Match(
                    "/tmp/lib.jar", "example/Parser.class", 0, "example.Parser", List.of("([B)V"))),
            true,
            "present",
            "POM",
            null,
            true);
    final JsonNode payload = ForbiddenCodeAssessmentCodec.write(List.of(assessment));
    final ObjectNode badBoolean = ((ObjectNode) payload.get(0)).deepCopy();
    badBoolean.put("complete", "true");
    final ObjectNode extra = ((ObjectNode) payload.get(0)).deepCopy();
    extra.put("unexpected", true);
    final ObjectNode badStatus = ((ObjectNode) payload.get(0)).deepCopy();
    badStatus.put("status", "INVENTED");
    final ObjectNode contradictory = ((ObjectNode) payload.get(0)).deepCopy();
    contradictory.put("versionApplicability", "NOT_APPLICABLE");
    assertAll(
        () -> assertThat(ForbiddenCodeAssessmentCodec.read(payload)).containsExactly(assessment),
        () ->
            assertThatThrownBy(
                    () ->
                        ForbiddenCodeAssessmentCodec.read(
                            com.fasterxml.jackson.databind.node.JsonNodeFactory.instance
                                .arrayNode()
                                .add(badBoolean)))
                .hasMessageContaining("complete"),
        () ->
            assertThatThrownBy(
                    () ->
                        ForbiddenCodeAssessmentCodec.read(
                            com.fasterxml.jackson.databind.node.JsonNodeFactory.instance
                                .arrayNode()
                                .add(extra)))
                .hasMessageContaining("fields"),
        () ->
            assertThatThrownBy(
                    () ->
                        ForbiddenCodeAssessmentCodec.read(
                            com.fasterxml.jackson.databind.node.JsonNodeFactory.instance
                                .arrayNode()
                                .add(badStatus)))
                .hasMessageContaining("status"),
        () ->
            assertThatThrownBy(
                    () ->
                        ForbiddenCodeAssessmentCodec.read(
                            com.fasterxml.jackson.databind.node.JsonNodeFactory.instance
                                .arrayNode()
                                .add(contradictory)))
                .hasMessageContaining("NOT_APPLICABLE"));
  }

  @Test
  void rejectsContradictoryAndInvalidPersistedEvidence() throws Exception {
    final ObjectNode valid =
        (ObjectNode) ForbiddenCodeAssessmentCodec.write(List.of(sample())).get(0);
    final ObjectNode noMatches = valid.deepCopy();
    noMatches.putArray("matches");
    final ObjectNode unknownVersion = valid.deepCopy();
    unknownVersion.put("versionApplicability", "UNKNOWN");
    final ObjectNode passWithMatches = valid.deepCopy();
    passWithMatches.put("status", "PASS");
    final ObjectNode noComponentViolation = valid.deepCopy();
    noComponentViolation.put("versionApplicability", "NO_COMPONENT");
    noComponentViolation.putNull("componentVersion");
    final ObjectNode unknownComplete = valid.deepCopy();
    unknownComplete.put("status", "UNKNOWN");
    unknownComplete.putArray("matches");
    final ObjectNode invalidCve = valid.deepCopy();
    invalidCve.put("cveId", "bad");
    final ObjectNode invalidRange = valid.deepCopy();
    invalidRange.put("versionScope", "[1,2");
    final ObjectNode invalidSymbol = valid.deepCopy();
    invalidSymbol.put("symbol", "Parser#bad");
    final ObjectNode invalidUrl = valid.deepCopy();
    invalidUrl.put("sourceUrl", "file:///tmp/a");
    final ObjectNode invalidProvenance = valid.deepCopy();
    invalidProvenance.put("provenance", " ");
    final ObjectNode invalidEvidence = valid.deepCopy();
    invalidEvidence.put("evidenceKind", "GUESS");
    final ObjectNode invalidTier = valid.deepCopy();
    ((ObjectNode) invalidTier.withArray("matches").get(0)).put("tier", 8);
    final ObjectNode invalidDescriptor = valid.deepCopy();
    ((ObjectNode) invalidDescriptor.withArray("matches").get(0))
        .putArray("descriptors")
        .add("(V)V");
    final ObjectNode partial = valid.deepCopy();
    partial.put("complete", false);
    final ObjectNode runtime = valid.deepCopy();
    runtime.put("componentKind", "JAVA_RUNTIME");
    runtime.putNull("componentIdentity");
    runtime.putNull("componentVersion");
    runtime.put("versionApplicability", "UNKNOWN");
    runtime.put("status", "UNKNOWN");
    runtime.put("evidenceKind", "RUNTIME_REACHABILITY");
    runtime.putNull("provider");
    runtime.putArray("matches");
    runtime.put("complete", false);
    assertAll(
        () -> rejects(noMatches),
        () -> rejects(unknownVersion),
        () -> rejects(passWithMatches),
        () -> rejects(noComponentViolation),
        () -> rejects(unknownComplete),
        () -> rejects(invalidCve),
        () -> rejects(invalidRange),
        () -> rejects(invalidSymbol),
        () -> rejects(invalidUrl),
        () -> rejects(invalidProvenance),
        () -> rejects(invalidEvidence),
        () -> rejects(invalidTier),
        () -> rejects(invalidDescriptor),
        () ->
            assertThat(ForbiddenCodeAssessmentCodec.read(array(partial)))
                .singleElement()
                .extracting(ForbiddenCodeAssessment::complete)
                .isEqualTo(false),
        () ->
            assertThat(ForbiddenCodeAssessmentCodec.read(array(runtime)))
                .singleElement()
                .extracting(ForbiddenCodeAssessment::componentIdentity)
                .isNull());
  }

  private static void rejects(final ObjectNode row) {
    assertThatThrownBy(() -> ForbiddenCodeAssessmentCodec.read(array(row)))
        .isInstanceOf(java.io.IOException.class);
  }

  @Test
  void directInvocationMustIdentifyAnApplicableRuntimeMethodAndCallSite() throws Exception {
    final ObjectNode runtime =
        (ObjectNode) ForbiddenCodeAssessmentCodec.write(List.of(sample())).get(0);
    runtime.put("componentKind", "JAVA_RUNTIME");
    runtime.put("componentIdentity", "Java Runtime");
    runtime.put("componentVersion", "21");
    runtime.put("versionScope", "(,)");
    runtime.put("symbol", "java.util.Base64.Decoder#decode(byte[])");
    runtime.put("evidenceKind", "DIRECT_RUNTIME_CALL");
    final ObjectNode match = (ObjectNode) runtime.withArray("matches").get(0);
    match.put("resolvedOwner", "java.util.Base64$Decoder");
    match.putArray("descriptors").add("([B)[B");
    final ObjectNode wrongArity = runtime.deepCopy();
    ((ObjectNode) wrongArity.withArray("matches").get(0)).putArray("descriptors").add("()V");
    final ObjectNode wrongArgument = runtime.deepCopy();
    ((ObjectNode) wrongArgument.withArray("matches").get(0)).putArray("descriptors").add("([I)[B");
    final ObjectNode wrongOwner = runtime.deepCopy();
    ((ObjectNode) wrongOwner.withArray("matches").get(0)).put("resolvedOwner", "java.lang.System");
    final ObjectNode wrongTier = runtime.deepCopy();
    ((ObjectNode) wrongTier.withArray("matches").get(0)).put("tier", 22);
    final ObjectNode wrongComponent = runtime.deepCopy();
    wrongComponent.put("componentKind", "PROJECT_OUTPUT");
    final ObjectNode classTarget = runtime.deepCopy();
    classTarget.put("symbol", "java.util.Base64.Decoder");
    final ObjectNode unidentifiedCall = runtime.deepCopy();
    ((ObjectNode) unidentifiedCall.withArray("matches").get(0)).putNull("entry");
    final ObjectNode declarationOnly = runtime.deepCopy();
    declarationOnly.put("evidenceKind", "PHYSICAL_DECLARATIONS");
    final ObjectNode noRuntime = runtime.deepCopy();
    noRuntime.putNull("componentVersion");
    final ObjectNode unknownRuntime = noRuntime.deepCopy();
    unknownRuntime.putNull("componentIdentity");
    unknownRuntime.putNull("provider");
    unknownRuntime.put("versionApplicability", "UNKNOWN");
    assertAll(
        () ->
            assertThat(ForbiddenCodeAssessmentCodec.read(array(runtime)))
                .singleElement()
                .extracting(ForbiddenCodeAssessment::evidenceKind)
                .isEqualTo("DIRECT_RUNTIME_CALL"),
        () -> rejects(wrongComponent),
        () -> rejects(classTarget),
        () -> rejects(unidentifiedCall),
        () -> rejects(wrongArity),
        () -> rejects(wrongArgument),
        () -> rejects(wrongOwner),
        () -> rejects(wrongTier),
        () -> rejects(noRuntime),
        () ->
            assertThat(ForbiddenCodeAssessmentCodec.read(array(unknownRuntime)))
                .singleElement()
                .satisfies(
                    row ->
                        assertAll(
                            () ->
                                assertThat(row.status())
                                    .isEqualTo(ForbiddenCodeAssessment.Status.VIOLATION),
                            () ->
                                assertThat(row.versionApplicability())
                                    .isEqualTo(
                                        ForbiddenCodeAssessment.VersionApplicability.UNKNOWN))),
        () -> rejects(declarationOnly));
  }

  private static JsonNode array(final ObjectNode row) {
    return com.fasterxml.jackson.databind.node.JsonNodeFactory.instance.arrayNode().add(row);
  }

  private static ForbiddenCodeAssessment sample() {
    return new ForbiddenCodeAssessment(
        "CVE-2026-12345",
        "example.Parser#parse(byte[])",
        ForbiddenCodeAssessment.ComponentKind.MAVEN_ARTIFACT,
        "example:lib:jar:1",
        "[1]",
        "1",
        21,
        true,
        ForbiddenCodeAssessment.VersionApplicability.APPLICABLE,
        ForbiddenCodeAssessment.Mode.OBSERVED,
        ForbiddenCodeAssessment.Status.VIOLATION,
        "PHYSICAL_DECLARATIONS",
        "/tmp/lib.jar",
        List.of(
            new ForbiddenCodeAssessment.Match(
                "/tmp/lib.jar", "example/Parser.class", 0, "example.Parser", List.of("([B)V"))),
        true,
        "present",
        "POM",
        null,
        true);
  }
}
