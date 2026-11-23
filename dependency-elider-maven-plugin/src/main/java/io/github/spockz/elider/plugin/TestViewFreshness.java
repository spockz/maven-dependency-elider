/* WHY: Rejects reused test additions when clean-build inputs have changed. */

package io.github.spockz.elider.plugin;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.spockz.elider.model.HexDigest;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;
import java.util.stream.Stream;

/** Persists a strict fingerprint of inputs used by automatic test additions. */
@SuppressWarnings({
  "PMD.CommentDefaultAccessModifier",
  "PMD.CommentRequired",
  "PMD.CyclomaticComplexity",
  "PMD.TestClassWithoutTestCases",
  "PMD.TooManyMethods",
  "PMD.UseConcurrentHashMap"
})
final class TestViewFreshness {
  private static final int SCHEMA_VERSION = 1;
  private static final String FORMAT_ID = "elider-test-view-freshness";
  private static final String CLEAN_INSTRUCTION = "Run Maven clean test to rebuild test additions.";
  private static final String SCHEMA_FIELD = "schemaVersion";
  private static final String FORMAT_FIELD = "formatId";
  private static final String FINGERPRINT_FIELD = "fingerprint";
  private static final String CATEGORIES_FIELD = "categories";
  private static final List<String> CATEGORY_NAMES =
      List.of("sources", "test-output", "main-output", "artifacts", "options-runtime");
  private static final ObjectMapper JSON =
      new ObjectMapper()
          .enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION)
          .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);

  private TestViewFreshness() {
    throw new AssertionError("No instances");
  }

  /** Records or verifies inputs from a successful clean preparation. */
  static void verifyOrRecord(
      final Path manifest,
      final boolean cleanedThisInvocation,
      final Path testOutput,
      final Path mainOutput,
      final List<Path> testSourceRoots,
      final List<TestAdditionsAnalyzer.ArtifactInput> originals,
      final Map<String, String> compilerRuntimeOptions)
      throws IOException {
    Objects.requireNonNull(manifest, "manifest");
    Objects.requireNonNull(testOutput, "testOutput");
    Objects.requireNonNull(mainOutput, "mainOutput");
    Objects.requireNonNull(testSourceRoots, "testSourceRoots");
    Objects.requireNonNull(originals, "originals");
    Objects.requireNonNull(compilerRuntimeOptions, "compilerRuntimeOptions");
    final Map<String, String> categories =
        categoryDigests(testOutput, mainOutput, testSourceRoots, originals, compilerRuntimeOptions);
    if (cleanedThisInvocation) {
      final ObjectNode document = JSON.createObjectNode();
      document.put(SCHEMA_FIELD, SCHEMA_VERSION);
      document.put(FORMAT_FIELD, FORMAT_ID);
      document.put(FINGERPRINT_FIELD, overallFingerprint(categories));
      final ObjectNode categoryDocument = document.putObject(CATEGORIES_FIELD);
      categories.forEach(categoryDocument::put);
      final Path output = manifest.toAbsolutePath().normalize();
      final Path parent = output.getParent();
      if (parent == null) {
        throw new IOException("Test-view freshness manifest has no parent: " + output);
      }
      Files.createDirectories(parent);
      JSON.writeValue(output.toFile(), document);
    } else {
      verify(manifest, categories);
    }
  }

  private static void verify(final Path manifest, final Map<String, String> currentCategories)
      throws IOException {
    if (!Files.isRegularFile(manifest)) {
      throw stale("Test-view freshness manifest is missing");
    }
    final JsonNode document;
    try {
      document = JSON.readValue(manifest.toFile(), JsonNode.class);
    } catch (final IOException failure) {
      throw new IOException(
          "Test-view freshness manifest is malformed. " + CLEAN_INSTRUCTION, failure);
    }
    if (!validManifest(document)) {
      throw stale("Test-view freshness manifest is incompatible or malformed");
    }
    final JsonNode previousCategories = document.path(CATEGORIES_FIELD);
    final Map<String, String> stored = new LinkedHashMap<>();
    for (final String category : CATEGORY_NAMES) {
      stored.put(category, previousCategories.path(category).textValue());
    }
    if (!document.path(FINGERPRINT_FIELD).textValue().equals(overallFingerprint(stored))) {
      throw stale("Test-view freshness manifest is inconsistent");
    }
    final List<String> changed = new ArrayList<>();
    for (final String category : CATEGORY_NAMES) {
      if (!currentCategories.get(category).equals(stored.get(category))) {
        changed.add(category);
      }
    }
    if (!changed.isEmpty()) {
      throw stale("Test-view inputs changed in " + String.join(", ", changed));
    }
  }

  private static boolean validManifest(final JsonNode document) {
    return document != null
        && document.isObject()
        && document.size() == 4
        && validHeader(document)
        && validFingerprint(document.path(FINGERPRINT_FIELD))
        && validCategories(document.path(CATEGORIES_FIELD));
  }

  private static boolean validHeader(final JsonNode document) {
    final JsonNode schema = document.path(SCHEMA_FIELD);
    final JsonNode format = document.path(FORMAT_FIELD);
    return schema.isIntegralNumber()
        && schema.canConvertToInt()
        && schema.intValue() == SCHEMA_VERSION
        && format.isTextual()
        && FORMAT_ID.equals(format.textValue());
  }

  private static boolean validFingerprint(final JsonNode fingerprint) {
    return fingerprint.isTextual() && HexDigest.isLowercaseHex(fingerprint.textValue(), 64);
  }

  private static boolean validCategories(final JsonNode categories) {
    if (!categories.isObject() || categories.size() != CATEGORY_NAMES.size()) {
      return false;
    }
    for (final String category : CATEGORY_NAMES) {
      if (!validFingerprint(categories.path(category))) {
        return false;
      }
    }
    return true;
  }

  private static String overallFingerprint(final Map<String, String> categories) {
    final List<String> values = new ArrayList<>(CATEGORY_NAMES.size() * 2);
    for (final String name : CATEGORY_NAMES) {
      values.add(name);
      values.add(categories.get(name));
    }
    return HexDigest.sha256LengthPrefixed(values);
  }

  private static IOException stale(final String reason) {
    return new IOException(reason + ". " + CLEAN_INSTRUCTION);
  }

  private static Map<String, String> categoryDigests(
      final Path testOutput,
      final Path mainOutput,
      final List<Path> testSourceRoots,
      final List<TestAdditionsAnalyzer.ArtifactInput> originals,
      final Map<String, String> compilerRuntimeOptions)
      throws IOException {
    final Map<Path, String> digests = new HashMap<>();
    final Map<String, String> categories = new LinkedHashMap<>();
    final List<String> sourceFields = new ArrayList<>();
    sourceFields.add(Integer.toString(testSourceRoots.size()));
    for (final Path root : testSourceRoots) {
      directoryFields(sourceFields, Objects.requireNonNull(root, "testSourceRoot"), digests);
    }
    categories.put("sources", HexDigest.sha256LengthPrefixed(sourceFields));
    final List<String> testFields = new ArrayList<>();
    directoryFields(testFields, testOutput, digests);
    categories.put("test-output", HexDigest.sha256LengthPrefixed(testFields));
    final List<String> mainFields = new ArrayList<>();
    directoryFields(mainFields, mainOutput, digests);
    categories.put("main-output", HexDigest.sha256LengthPrefixed(mainFields));
    final List<String> artifactFields = new ArrayList<>();
    artifactFields.add(Integer.toString(originals.size()));
    for (final TestAdditionsAnalyzer.ArtifactInput artifact : originals) {
      Objects.requireNonNull(artifact, "artifact");
      artifactFields.add(artifact.identity());
      artifactFields.add(Boolean.toString(artifact.testScoped()));
      fileFields(artifactFields, artifact.originalJar(), digests);
      artifactFields.add(Boolean.toString(artifact.effectiveRuntimeJar().isPresent()));
      if (artifact.effectiveRuntimeJar().isPresent()) {
        fileFields(artifactFields, artifact.effectiveRuntimeJar().orElseThrow(), digests);
      }
    }
    categories.put("artifacts", HexDigest.sha256LengthPrefixed(artifactFields));
    final List<String> optionFields = new ArrayList<>();
    optionFields.add(Integer.toString(Runtime.version().feature()));
    optionFields.add(Integer.toString(compilerRuntimeOptions.size()));
    for (final Map.Entry<String, String> option :
        new TreeMap<>(compilerRuntimeOptions).entrySet()) {
      optionFields.add(Objects.requireNonNull(option.getKey(), "compilerRuntimeOption key"));
      optionFields.add(Objects.requireNonNull(option.getValue(), "compilerRuntimeOption value"));
    }
    categories.put("options-runtime", HexDigest.sha256LengthPrefixed(optionFields));
    return categories;
  }

  private static void directoryFields(
      final List<String> fields, final Path directory, final Map<Path, String> digests)
      throws IOException {
    final Path root = directory.toAbsolutePath().normalize();
    fields.add(root.toString());
    if (Files.notExists(root)) {
      fields.add("missing");
      return;
    }
    if (!Files.isDirectory(root)) {
      throw new IOException("Expected a test-view input directory: " + root);
    }
    fields.add("directory");
    try (Stream<Path> paths = Files.walk(root)) {
      final List<Path> included = paths.filter(Files::isRegularFile).sorted().toList();
      fields.add(Integer.toString(included.size()));
      for (final Path path : included) {
        fields.add(root.relativize(path).toString().replace('\\', '/'));
        fields.add(digest(path, digests));
      }
    }
  }

  private static void fileFields(
      final List<String> fields, final Path input, final Map<Path, String> digests)
      throws IOException {
    final Path path = input.toAbsolutePath().normalize();
    if (!Files.isRegularFile(path)) {
      throw new IOException("Test-view artifact input is missing: " + path);
    }
    fields.add(path.toString());
    fields.add(digest(path, digests));
  }

  private static String digest(final Path path, final Map<Path, String> digests)
      throws IOException {
    final Path absolute = path.toAbsolutePath().normalize();
    String value = digests.get(absolute);
    if (value == null) {
      value = HexDigest.sha256(absolute);
      digests.put(absolute, value);
    }
    return value;
  }
}
