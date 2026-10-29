/* WHY: Binds generated-output targets and staging files to inventory freshness checks. */

package io.github.spockz.elider.plugin;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HexFormat;
import java.util.LinkedHashSet;
import java.util.List;

/** Captures exact generated-output paths and bytes. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class MavenPreconditionOutputState {
  private MavenPreconditionOutputState() {}

  static List<Path> normalizedPaths(final Collection<Path> paths) {
    final List<Path> normalized =
        paths.stream().map(path -> path.toAbsolutePath().normalize()).sorted().toList();
    if (new LinkedHashSet<>(normalized).size() != normalized.size()) {
      throw new IllegalArgumentException("Duplicate generated output path");
    }
    return normalized;
  }

  static List<String> identity(final List<Path> outputs, final List<Path> stages) {
    final List<String> identity = new ArrayList<>();
    outputs.forEach(path -> identity.add("output\0" + path));
    stages.forEach(path -> identity.add("stage\0" + path));
    return List.copyOf(identity);
  }

  static List<String> states(final List<Path> outputs) throws IOException {
    final List<String> states = new ArrayList<>();
    for (final Path output : outputs) {
      if (!canonicalizedPath(output).equals(output)) {
        throw new IOException("Known generated output path is not canonical: " + output);
      }
      if (definitelyAbsent(output)) {
        states.add("output\0" + output + "\0MISSING");
      } else {
        states.add("output\0" + output + "\0" + ArtifactFileDigest.sha256(output));
      }
    }
    return List.copyOf(states);
  }

  static String fingerprint(
      final List<String> rootIdentity,
      final List<String> outputIdentity,
      final List<String> outputStates) {
    try {
      final ByteArrayOutputStream bytes = new ByteArrayOutputStream();
      try (DataOutputStream output = new DataOutputStream(bytes)) {
        writeValues(output, rootIdentity);
        output.writeInt(-1);
        writeValues(output, outputIdentity);
        output.writeInt(-1);
        writeValues(output, outputStates);
      }
      return HexFormat.of()
          .formatHex(MessageDigest.getInstance("SHA-256").digest(bytes.toByteArray()));
    } catch (final IOException exception) {
      throw new IllegalStateException("Could not fingerprint generated-output state", exception);
    } catch (final NoSuchAlgorithmException exception) {
      throw new IllegalStateException("SHA-256 is unavailable", exception);
    }
  }

  static boolean definitelyAbsent(final Path path) throws IOException {
    if (Files.notExists(path, LinkOption.NOFOLLOW_LINKS)) {
      return true;
    }
    if (!Files.exists(path, LinkOption.NOFOLLOW_LINKS)) {
      throw new IOException("Cannot determine generated output path state: " + path);
    }
    return false;
  }

  static Path canonicalizedPath(final Path path) throws IOException {
    final Path normalized = path.toAbsolutePath().normalize();
    Path existing = normalized;
    while (existing != null && !Files.exists(existing, LinkOption.NOFOLLOW_LINKS)) {
      existing = existing.getParent();
    }
    if (existing == null) {
      throw new IOException("Generated output path has no existing ancestor: " + normalized);
    }
    final Path canonicalExisting = existing.toRealPath();
    return canonicalExisting.resolve(existing.relativize(normalized)).normalize();
  }

  private static void writeValues(final DataOutputStream output, final List<String> values)
      throws IOException {
    for (final String value : values) {
      output.writeUTF(value);
    }
  }
}
