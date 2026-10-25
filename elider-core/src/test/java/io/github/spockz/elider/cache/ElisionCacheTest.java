/* WHY: Verifies deterministic fingerprints and durable cache round trips and misses. */

package io.github.spockz.elider.cache;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.spockz.elider.engine.DependencyPruner;
import io.github.spockz.elider.engine.PruneConfig;
import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.ArtifactFileRef;
import io.github.spockz.elider.model.ElisionDecision;
import io.github.spockz.elider.model.OriginEvidence;
import io.github.spockz.elider.model.TraceData;
import io.github.spockz.elider.scanner.ArtifactClassIndex;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Verifies deterministic fingerprints, complete records, and explicit misses. */
@SuppressWarnings({"PMD.AvoidDuplicateLiterals", "PMD.CommentDefaultAccessModifier"})
final class ElisionCacheTest {
  /** Version labels the semantics covered by the cache fingerprint fixture. */
  private static final String SEMANTICS_VERSION = "origin-v1";

  /** Temporary files isolate cache inputs and records from the repository. */
  @TempDir private Path temp;

  /** Creates each test fixture with an injected temporary directory. */
  ElisionCacheTest() {
    // JUnit injects the temporary directory after constructing this fixture.
  }

  @Test
  @SuppressWarnings("PMD.UnitTestContainsTooManyAsserts")
  void fingerprintIsOrderIndependentAndUsesFreshMetadataAndAllInputs() throws Exception {
    final Path one = Files.writeString(temp.resolve("one.jar"), "one");
    final Path two = Files.writeString(temp.resolve("two.jar"), "two");
    final Path trace = Files.writeString(temp.resolve("trace"), "trace");
    final Path secondTrace = Files.writeString(temp.resolve("second-trace"), "second trace");
    final ArtifactCoordinate firstCoordinate = ArtifactCoordinate.of("g", "a", "1");
    final ArtifactCoordinate secondCoordinate =
        new ArtifactCoordinate("g", "b", "null", "jar", "", "runtime");
    final Set<ArtifactFileRef> refs =
        Set.of(
            ArtifactFileRef.fromPath(firstCoordinate, one),
            ArtifactFileRef.fromPath(secondCoordinate, two));
    final Set<ArtifactFileRef> reversedRefs =
        new LinkedHashSet<>(
            List.of(
                ArtifactFileRef.fromPath(secondCoordinate, two),
                ArtifactFileRef.fromPath(firstCoordinate, one)));
    final Set<Path> traces = new LinkedHashSet<>(List.of(trace, secondTrace));
    final Set<Path> reversedTraces = new LinkedHashSet<>(List.of(secondTrace, trace));
    final long fingerprint =
        FingerprintEngine.fingerprint(refs, traces, new PruneConfig(), SEMANTICS_VERSION);
    assertThat(
            FingerprintEngine.fingerprint(
                reversedRefs, reversedTraces, new PruneConfig(), SEMANTICS_VERSION))
        .isEqualTo(fingerprint);
    final Set<ArtifactFileRef> staleRefs =
        new LinkedHashSet<>(
            List.of(
                new ArtifactFileRef(firstCoordinate, one, 0L, 0L),
                ArtifactFileRef.fromPath(secondCoordinate, two)));
    assertThat(
            FingerprintEngine.fingerprint(staleRefs, traces, new PruneConfig(), SEMANTICS_VERSION))
        .isEqualTo(fingerprint);
    assertThat(FingerprintEngine.fingerprint(refs, traces, new PruneConfig(), "origin-v2"))
        .isNotEqualTo(fingerprint);
    Files.writeString(trace, "changed-size");
    assertThat(FingerprintEngine.fingerprint(refs, traces, new PruneConfig(), SEMANTICS_VERSION))
        .isNotEqualTo(fingerprint);
    assertThatThrownBy(
            () ->
                FingerprintEngine.fingerprint(
                    Set.of(
                        ArtifactFileRef.fromPath(firstCoordinate, one),
                        ArtifactFileRef.fromPath(firstCoordinate, two)),
                    Set.of(trace),
                    new PruneConfig(),
                    SEMANTICS_VERSION))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(
            () ->
                FingerprintEngine.fingerprint(
                    Set.of(
                        ArtifactFileRef.fromPath(firstCoordinate, one),
                        new ArtifactFileRef(firstCoordinate, one, 0L, 0L)),
                    Set.of(trace),
                    new PruneConfig(),
                    SEMANTICS_VERSION))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(
            () ->
                FingerprintEngine.fingerprint(
                    refs, Set.of(temp.resolve("missing")), new PruneConfig(), SEMANTICS_VERSION))
        .isInstanceOf(IOException.class);
  }

  @Test
  @SuppressWarnings("PMD.UnitTestContainsTooManyAsserts")
  void everyCoordinateAndConfigurationFieldContributesToFingerprint() throws Exception {
    final Path artifact = Files.writeString(temp.resolve("dimension.jar"), "content");
    final Path trace = Files.writeString(temp.resolve("dimension.trace"), "trace");
    final ArtifactCoordinate base = new ArtifactCoordinate("g", "a", null, "jar", "", "compile");
    final PruneConfig originalConfig = new PruneConfig();
    final long original = fingerprint(base, artifact, trace, originalConfig);
    final PruneConfig defaultConfig = new PruneConfig();
    final List<ArtifactCoordinate> variants =
        List.of(
            new ArtifactCoordinate("other", "a", null, "jar", "", "compile"),
            new ArtifactCoordinate("g", "other", null, "jar", "", "compile"),
            new ArtifactCoordinate("g", "a", "null", "jar", "", "compile"),
            new ArtifactCoordinate("g", "a", null, "war", "", "compile"),
            new ArtifactCoordinate("g", "a", null, "jar", "tests", "compile"),
            new ArtifactCoordinate("g", "a", null, "jar", "", "runtime"));
    for (final ArtifactCoordinate coordinate : variants) {
      assertThat(fingerprint(coordinate, artifact, trace, defaultConfig)).isNotEqualTo(original);
    }
    final List<PruneConfig> configVariants =
        List.of(
            new PruneConfig(Set.of("compile"), Set.of()),
            new PruneConfig(Set.of(), Set.of(base)),
            new PruneConfig(Set.of(), Set.of(), Set.of("test")),
            new PruneConfig(Set.of(), Set.of(), Set.of("compile", "runtime"), Set.of(base)));
    for (final PruneConfig config : configVariants) {
      assertThat(fingerprint(base, artifact, trace, config)).isNotEqualTo(original);
    }
    final PruneConfig firstOrderedConfig =
        new PruneConfig(
            new LinkedHashSet<>(List.of("compile", "runtime")),
            Set.of(),
            Set.of("compile", "runtime"),
            Set.of());
    final PruneConfig reversedOrderedConfig =
        new PruneConfig(
            new LinkedHashSet<>(List.of("runtime", "compile")),
            Set.of(),
            new LinkedHashSet<>(List.of("runtime", "compile")),
            Set.of());
    assertThat(fingerprint(base, artifact, trace, firstOrderedConfig))
        .isEqualTo(fingerprint(base, artifact, trace, reversedOrderedConfig));
    final Path relocatedTrace = Files.writeString(temp.resolve("other.trace"), "trace");
    assertThat(
            FingerprintEngine.fingerprint(
                Set.of(ArtifactFileRef.fromPath(base, artifact)),
                Set.of(trace, relocatedTrace),
                new PruneConfig(),
                SEMANTICS_VERSION))
        .isNotEqualTo(original);
    Files.writeString(artifact, "new-size");
    assertThat(fingerprint(base, artifact, trace, new PruneConfig())).isNotEqualTo(original);
  }

  /** Explains why each fixture dimension must affect the stable key. */
  private long fingerprint(
      final ArtifactCoordinate coordinate,
      final Path artifact,
      final Path trace,
      final PruneConfig config)
      throws IOException {
    return FingerprintEngine.fingerprint(
        Set.of(ArtifactFileRef.fromPath(coordinate, artifact)),
        Set.of(trace),
        config,
        SEMANTICS_VERSION);
  }

  @Test
  @SuppressWarnings("PMD.UnitTestContainsTooManyAsserts")
  void completeDecisionRoundTripsAndCorruptionIsAnExplicitMiss() throws Exception {
    Files.writeString(temp.resolve("artifact.jar"), "jar");
    final ArtifactCoordinate retained = ArtifactCoordinate.of("g", "a", "1");
    final ArtifactCoordinate elided =
        new ArtifactCoordinate("g", "b", null, "jar", "tests", "test");
    final Set<ArtifactCoordinate> inventory = Set.of(retained, elided);
    final ElisionDecision decision =
        new ElisionDecision(
            Set.of(retained),
            Set.of(elided),
            Map.of(retained, Set.of("p.Used"), elided, Set.of()),
            Map.of(retained, Set.of(), elided, Set.of("p.Other")),
            42L);
    final Path cache = temp.resolve("cache.bin");
    final ElisionCache store = new ElisionCache();
    final Set<ArtifactCoordinate> reversedInventory =
        new LinkedHashSet<>(List.of(elided, retained));
    assertThat(ElisionCacheWriter.encode(17L, inventory, decision))
        .isEqualTo(ElisionCacheWriter.encode(17L, reversedInventory, decision));
    store.store(cache, 17L, inventory, decision);
    final ElisionCache.Lookup hit = store.load(cache, 17L, inventory);
    assertThat(hit.hit()).isTrue();
    assertThat(hit.decision()).isEqualTo(decision);
    assertThatThrownBy(() -> hit.decision().retainedArtifacts().clear())
        .isInstanceOf(UnsupportedOperationException.class);
    assertThat(store.load(cache, 18L, inventory).hit()).isFalse();
    final byte[] originalBytes = Files.readAllBytes(cache);
    byte[] bytes = originalBytes.clone();
    bytes[11] = 2;
    Files.write(cache, bytes);
    assertThat(store.load(cache, 17L, inventory).missReason()).contains("version");
    bytes = Arrays.copyOf(originalBytes, originalBytes.length + 1);
    Files.write(cache, bytes);
    assertThat(store.load(cache, 17L, inventory).missReason()).contains("trailing");
    bytes = originalBytes.clone();
    bytes[bytes.length - 33] ^= 1;
    Files.write(cache, bytes);
    assertThat(store.load(cache, 17L, inventory).missReason()).contains("checksum");
    final byte[] payload =
        Arrays.copyOfRange(
            originalBytes, Long.BYTES + Integer.BYTES * 2, originalBytes.length - 32);
    final byte[] payloadWithTrailingData = Arrays.copyOf(payload, payload.length + 1);
    final ByteArrayOutputStream invalidRecord = new ByteArrayOutputStream();
    try (DataOutputStream output = new DataOutputStream(invalidRecord)) {
      output.writeLong(ElisionCacheCodec.MAGIC);
      output.writeInt(ElisionCacheCodec.VERSION);
      output.writeInt(payloadWithTrailingData.length);
      output.write(payloadWithTrailingData);
      output.write(ElisionCacheCodec.checksum(payloadWithTrailingData));
    }
    Files.write(cache, invalidRecord.toByteArray());
    assertThat(store.load(cache, 17L, inventory).missReason()).contains("trailing payload");
    Files.write(cache, new byte[] {1, 2, 3});
    assertThat(store.load(cache, 17L, inventory).hit()).isFalse();
    Files.write(cache, new byte[64 * 1024 * 1024 + 1]);
    assertThat(store.load(cache, 17L, inventory).missReason()).isEqualTo("oversized");

    final ElisionDecision contradictory =
        new ElisionDecision(
            Set.of(retained),
            Set.of(retained),
            Map.of(retained, Set.of("p.Used"), elided, Set.of()),
            Map.of(retained, Set.of(), elided, Set.of("p.Other")),
            42L);
    Files.write(cache, ElisionCacheWriter.encode(17L, inventory, contradictory));
    assertThat(store.load(cache, 17L, inventory).hit()).isFalse();
    final ElisionDecision negativeDuration =
        new ElisionDecision(
            decision.retainedArtifacts(),
            decision.elidedArtifacts(),
            decision.retainedClassesPerArtifact(),
            decision.unusedClassesPerArtifact(),
            -1L);
    assertThatThrownBy(() -> store.store(cache, 17L, inventory, negativeDuration))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  @SuppressWarnings("PMD.UnitTestContainsTooManyAsserts")
  void missingCacheIsMissAndArtifactRelocationChangesFingerprint() throws Exception {
    final Path firstPath = Files.writeString(temp.resolve("a.jar"), "same");
    final Path secondPath = Files.writeString(temp.resolve("b.jar"), "same");
    final ArtifactCoordinate coordinate = ArtifactCoordinate.of("g", "a", "1");
    final long firstFingerprint =
        FingerprintEngine.fingerprint(
            Set.of(ArtifactFileRef.fromPath(coordinate, firstPath)),
            Set.of(),
            new PruneConfig(),
            SEMANTICS_VERSION);
    final long secondFingerprint =
        FingerprintEngine.fingerprint(
            Set.of(ArtifactFileRef.fromPath(coordinate, secondPath)),
            Set.of(),
            new PruneConfig(),
            SEMANTICS_VERSION);
    assertThat(firstFingerprint).isNotEqualTo(secondFingerprint);
    assertThat(
            new ElisionCache()
                .load(temp.resolve("absent"), firstFingerprint, Set.of(coordinate))
                .missReason())
        .isEqualTo("missing");
  }

  @Test
  void freshPrunerDecisionsWithExactUnknownAndMergedOriginsRoundTrip() throws Exception {
    final Path firstPath = Files.writeString(temp.resolve("first.jar"), "one");
    final Path secondPath = Files.writeString(temp.resolve("second.jar"), "two");
    final ArtifactFileRef first =
        ArtifactFileRef.fromPath(ArtifactCoordinate.of("g", "first", "1"), firstPath);
    final ArtifactFileRef second =
        ArtifactFileRef.fromPath(ArtifactCoordinate.of("g", "second", "1"), secondPath);
    final ArtifactClassIndex index =
        new ArtifactClassIndex(
            Map.of(first, Set.of("sample.Shared"), second, Set.of("sample.Shared")));
    final List<OriginEvidence> evidenceVariants =
        List.of(
            OriginEvidence.unknown(),
            new OriginEvidence(Set.of(firstPath.toAbsolutePath()), false),
            OriginEvidence.unknown()
                .merge(new OriginEvidence(Set.of(firstPath.toAbsolutePath()), false)));
    final DependencyPruner pruner = new DependencyPruner();
    final PruneConfig config = new PruneConfig();
    final ElisionCache codec = new ElisionCache();
    for (int indexOfEvidence = 0; indexOfEvidence < evidenceVariants.size(); indexOfEvidence++) {
      final TraceData trace =
          TraceData.fromClassOrigins(
              Map.of("sample.Shared", evidenceVariants.get(indexOfEvidence)));
      final ElisionDecision decision = pruner.prune(List.of(first, second), index, trace, config);
      final Path cache = temp.resolve("origin-" + indexOfEvidence + ".bin");
      final Set<ArtifactCoordinate> inventory = Set.of(first.coordinate(), second.coordinate());
      final long fingerprint =
          FingerprintEngine.fingerprint(
              List.of(first, second), List.of(), config, SEMANTICS_VERSION);
      codec.store(cache, fingerprint, inventory, decision);
      assertThat(codec.load(cache, fingerprint, inventory).decision()).isEqualTo(decision);
    }
  }

  @Test
  void changedModificationTimeChangesFingerprint() throws Exception {
    final Path artifact = Files.writeString(temp.resolve("timestamp.jar"), "same size");
    final Path trace = Files.writeString(temp.resolve("timestamp.trace"), "same size");
    final ArtifactCoordinate coordinate = ArtifactCoordinate.of("g", "time", "1");
    final long before = fingerprint(coordinate, artifact, trace, new PruneConfig());
    Files.setLastModifiedTime(artifact, FileTime.fromMillis(1_000L));

    assertThat(fingerprint(coordinate, artifact, trace, new PruneConfig())).isNotEqualTo(before);
  }
}
