/* WHY: Clears stale SBOM and VEX files only when their bytes match recorded
 * plugin output. */

package io.github.spockz.elider.plugin;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.File;
import java.io.IOException;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import org.apache.maven.model.Build;
import org.apache.maven.project.MavenProject;

@SuppressWarnings({"PMD.CommentDefaultAccessModifier", "PMD.CommentRequired"})
final class MavenGeneratedOutputs {
  private static final int SCHEMA_VERSION = 1;
  private static final String SCHEMA_FIELD = "schemaVersion";
  private static final String OUTPUTS_FIELD = "outputs";
  private static final ObjectMapper JSON =
      new ObjectMapper().enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION);

  private MavenGeneratedOutputs() {}

  static void record(final MavenProject project, final Collection<Path> generated)
      throws IOException {
    final Path manifest = Paths.manifestPath(project);
    final ArrayNode outputs = JSON.createArrayNode();
    final Set<Path> seen = new HashSet<>();
    for (final Path requested :
        generated.stream().sorted(Comparator.comparing(Path::toString)).toList()) {
      final Path path = requested.toAbsolutePath().normalize();
      if (seen.add(path) && Files.isRegularFile(path)) {
        final ObjectNode output = outputs.addObject();
        output.put("path", path.toString());
        output.put("sha256", ArtifactFileDigest.sha256(path));
      }
    }
    final ObjectNode document = JSON.createObjectNode();
    document.put(SCHEMA_FIELD, SCHEMA_VERSION);
    document.set(OUTPUTS_FIELD, outputs);
    writeAtomically(manifest, temporary -> JSON.writeValue(temporary.toFile(), document));
  }

  static Optional<String> unchangedOwnedOutputDigest(final MavenProject project, final Path output)
      throws IOException {
    final Path manifest = Paths.manifestPath(project);
    if (Files.notExists(manifest)) {
      return Optional.empty();
    }
    final Path normalizedTarget = output.toAbsolutePath().normalize();
    Optional<String> digest = Optional.empty();
    for (final Registry.OwnedOutput owned : Registry.read(manifest)) {
      if (owned.path().equals(normalizedTarget)
          && Files.isRegularFile(normalizedTarget)
          && ArtifactFileDigest.sha256(normalizedTarget).equals(owned.sha256())) {
        digest = Optional.of(owned.sha256());
      }
    }
    return digest;
  }

  static void writeAtomically(final Path target, final OutputWriter writer) throws IOException {
    final Path absolute = target.toAbsolutePath().normalize();
    final Path parent = absolute.getParent();
    if (parent == null) {
      throw new IOException("Generated output path has no parent directory: " + absolute);
    }
    final Path fileName = absolute.getFileName();
    if (fileName == null) {
      throw new IOException("Generated output path has no file name: " + absolute);
    }
    Files.createDirectories(parent);
    final Path temporary = Files.createTempFile(parent, "." + fileName + "-", ".tmp");
    try {
      writer.write(temporary);
      try {
        Files.move(
            temporary,
            absolute,
            StandardCopyOption.ATOMIC_MOVE,
            StandardCopyOption.REPLACE_EXISTING);
      } catch (final AtomicMoveNotSupportedException exception) {
        throw new IOException(
            "Filesystem cannot atomically publish output: " + absolute, exception);
      }
    } finally {
      Files.deleteIfExists(temporary);
    }
  }

  static Path manifestPath(final MavenProject project) {
    return Paths.manifestPath(project);
  }

  /** Writes one temporary file before atomic replacement of its target. */
  @FunctionalInterface
  interface OutputWriter {
    /** Writes complete output bytes to the supplied temporary path. */
    void write(Path temporary) throws IOException;
  }

  private static final class Registry {
    private static List<OwnedOutput> read(final Path manifest) throws IOException {
      final JsonNode document = readDocument(manifest);
      validateFields(document, Set.of(SCHEMA_FIELD, OUTPUTS_FIELD), manifest);
      validateSchema(document.get(SCHEMA_FIELD), manifest);
      final JsonNode outputs = document.get(OUTPUTS_FIELD);
      if (outputs == null || !outputs.isArray()) {
        throw new IOException("Malformed generated output registry: " + manifest);
      }
      final List<OwnedOutput> result = new ArrayList<>();
      final Set<Path> seen = new HashSet<>();
      for (final JsonNode output : outputs) {
        final OwnedOutput parsed = readOutput(output, manifest);
        if (!seen.add(parsed.path())) {
          throw new IOException("Duplicate generated output registry path: " + parsed.path());
        }
        result.add(parsed);
      }
      return List.copyOf(result);
    }

    private static JsonNode readDocument(final Path manifest) throws IOException {
      final JsonNode document;
      try (JsonParser parser = JSON.getFactory().createParser(Files.newInputStream(manifest))) {
        document = JSON.readTree(parser);
        if (parser.nextToken() != null) {
          throw new IOException("Trailing data in generated output registry: " + manifest);
        }
      }
      if (document == null || !document.isObject()) {
        throw new IOException("Malformed generated output registry: " + manifest);
      }
      return document;
    }

    private static void validateSchema(final JsonNode version, final Path manifest)
        throws IOException {
      if (version == null
          || !version.isIntegralNumber()
          || !version.canConvertToInt()
          || version.intValue() != SCHEMA_VERSION) {
        throw new IOException("Unsupported generated output manifest schema version: " + manifest);
      }
    }

    private static OwnedOutput readOutput(final JsonNode output, final Path manifest)
        throws IOException {
      if (!output.isObject()) {
        throw new IOException("Malformed generated output entry: " + manifest);
      }
      validateFields(output, Set.of("path", "sha256"), manifest);
      final String path = textualField(output, "path", "Malformed generated output path", manifest);
      if (path.isBlank()) {
        throw new IOException("Malformed generated output path: " + manifest);
      }
      final String digest =
          textualField(output, "sha256", "Malformed generated output digest", manifest);
      if (!HexDigest.isLowercaseHex(digest, 64)) {
        throw new IOException("Malformed generated output digest: " + manifest);
      }
      return new OwnedOutput(Path.of(path).toAbsolutePath().normalize(), digest);
    }

    private static String textualField(
        final JsonNode object, final String field, final String diagnostic, final Path manifest)
        throws IOException {
      final JsonNode value = object.get(field);
      if (value == null || !value.isTextual()) {
        throw new IOException(diagnostic + ": " + manifest);
      }
      return value.textValue();
    }

    private static void validateFields(
        final JsonNode object, final Set<String> supported, final Path manifest)
        throws IOException {
      final java.util.Iterator<String> names = object.fieldNames();
      while (names.hasNext()) {
        final String name = names.next();
        if (!supported.contains(name)) {
          throw new IOException(
              "Unsupported generated output registry field " + name + ": " + manifest);
        }
      }
    }

    private record OwnedOutput(Path path, String sha256) {}
  }

  /** Resolves configured or standard paths for generated Maven outputs. */
  @SuppressWarnings("PMD.CommentDefaultAccessModifier")
  static final class Paths {
    private Paths() {}

    /** Returns every output path recorded after a successful elide run. */
    static List<Path> generatedOutputPaths(
        final MavenProject project,
        final File sbom,
        final File baseline,
        final File vex,
        final boolean vexWasWritten) {
      final List<Path> outputs =
          new ArrayList<>(
              List.of(
                  outputFile(sbom, project, "dependency-elider-sbom.cdx.json").toPath(),
                  outputFile(baseline, project, "baseline-sbom.cdx.json").toPath(),
                  buildDirectory(project)
                      .resolve(AdvisoryJdkModulesAnalyzer.ADVISORY_MODULES_FILENAME)));
      if (vexWasWritten) {
        outputs.add(outputFile(vex, project, "dependency-elider.openvex.json").toPath());
      }
      outputs.addAll(MavenSbomWriter.embeddedSbomPaths(project));
      return List.copyOf(outputs);
    }

    /** Resolves a configured output file or its standard build-directory fallback. */
    static File outputFile(
        final File configured, final MavenProject project, final String defaultName) {
      return configured != null
          ? configured
          : buildDirectory(project).resolve(defaultName).toFile();
    }

    private static Path buildDirectory(final MavenProject project) {
      final Build build = project.getBuild();
      final String configuredDirectory = build == null ? null : build.getDirectory();
      return configuredDirectory == null
          ? projectDirectory(project).resolve("target")
          : Path.of(configuredDirectory);
    }

    @SuppressWarnings("PMD.LawOfDemeter")
    private static Path projectDirectory(final MavenProject project) {
      final File projectDirectory = project.getBasedir();
      return projectDirectory == null ? Path.of(".") : Path.of(projectDirectory.getPath());
    }

    /** Returns the ownership registry path under Maven's configured build directory. */
    static Path manifestPath(final MavenProject project) {
      return buildDirectory(project)
          .resolve("dependency-elider-generated-outputs.json")
          .toAbsolutePath()
          .normalize();
    }
  }
}
