/* WHY: Verifies that sequential trimmed-output publication revalidates every analysis input. */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.trimmer.ArchiveSanitizer;
import io.github.spockz.elider.trimmer.ArtifactTrimRecord;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Checks that an earlier input cannot change during a later output publication. */
@SuppressWarnings("PMD.UnitTestContainsTooManyAsserts")
final class MavenDependencyTrimmerPublicationTest {
  /** Ordinal of the publication whose callback mutates the earlier input. */
  private static final int LATER_PUBLICATION = 2;

  /** Valid-shaped digests for the synthetic publication records. */
  private static final String ZERO_SHA_256 = "0".repeat(64);

  /** Valid-shaped SHA-1 value for synthetic publication records. */
  private static final String ZERO_SHA_1 = "0".repeat(40);

  /** Group identifier shared by fixture coordinates. */
  private static final String GROUP_ID = "org.example";

  /** Version shared by fixture coordinates. */
  private static final String VERSION = "1.0";

  /** Archive type shared by fixture coordinates. */
  private static final String JAR_TYPE = "jar";

  /** Temporary workspace for publication inputs and outputs. */
  @TempDir private Path temporaryDirectory;

  /** Creates the publication regression fixture. */
  @SuppressWarnings({"PMD.UncommentedEmptyConstructor", "PMD.CommentDefaultAccessModifier"})
  MavenDependencyTrimmerPublicationTest() {}

  @Test
  void rejectsEarlierInputMutationDuringLaterOutputPublication()
      throws IOException, java.security.NoSuchAlgorithmException {
    final Path firstInput = temporaryDirectory.resolve("first.jar");
    final Path secondInput = temporaryDirectory.resolve("second.jar");
    Files.writeString(firstInput, "first input before analysis");
    Files.writeString(secondInput, "second input remains unchanged");
    final String firstDigest = sha256(firstInput);
    final String secondDigest = sha256(secondInput);
    final Map<Path, String> inputDigests =
        Map.of(
            firstInput.toAbsolutePath().normalize(), firstDigest,
            secondInput.toAbsolutePath().normalize(), secondDigest);
    final ArchiveSanitizer.PreparedOutput firstOutput = preparedOutput("first", firstInput);
    final ArchiveSanitizer.PreparedOutput secondOutput = preparedOutput("second", secondInput);
    final AtomicInteger publicationCount = new AtomicInteger();

    assertThatThrownBy(
            () ->
                MavenDependencyTrimmer.publishOutputs(
                    List.of(firstOutput, secondOutput),
                    prepared -> {
                      Files.writeString(prepared.outputPath(), "published");
                      if (publicationCount.incrementAndGet() == LATER_PUBLICATION) {
                        Files.writeString(firstInput, "changed during the later publication");
                      }
                      return record(prepared);
                    },
                    inputDigests))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("dependency changed during trim analysis");

    assertThat(publicationCount.get()).isEqualTo(LATER_PUBLICATION);
    assertThat(temporaryDirectory.resolve("first-trimmed.jar")).exists();
    assertThat(temporaryDirectory.resolve("second-trimmed.jar")).exists();
    assertThat(Files.readString(firstInput)).isEqualTo("changed during the later publication");
  }

  private ArchiveSanitizer.PreparedOutput preparedOutput(
      final String artifactId, final Path originalPath) {
    return new ArchiveSanitizer.PreparedOutput(
        temporaryDirectory.resolve(artifactId + ".tmp"),
        temporaryDirectory.resolve(artifactId + "-trimmed.jar"),
        originalPath,
        originalPath,
        new ArtifactCoordinate(GROUP_ID, artifactId, VERSION, JAR_TYPE, "", artifactId),
        ZERO_SHA_256,
        ZERO_SHA_1,
        ZERO_SHA_256,
        ZERO_SHA_1,
        1,
        1);
  }

  private static ArtifactTrimRecord record(final ArchiveSanitizer.PreparedOutput prepared) {
    return new ArtifactTrimRecord(
        prepared.coordinate(),
        prepared.originalPath(),
        prepared.originalSha256(),
        prepared.originalSha1(),
        prepared.outputPath(),
        prepared.trimmedSha256(),
        prepared.trimmedSha1(),
        prepared.totalClasses(),
        prepared.retainedClasses());
  }

  private static String sha256(final Path path)
      throws IOException, java.security.NoSuchAlgorithmException {
    return HexFormat.of()
        .formatHex(MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(path)));
  }
}
