/* WHY: Verifies GraalVM reflection config parsing and failures using temporary local JSON files. */

package io.github.spockz.elider.trace;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIOException;

import io.github.spockz.elider.model.TraceData;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Covers GraalVM reflection configuration input. */
@SuppressWarnings({
  "PMD.UnitTestContainsTooManyAsserts",
  "PMD.UncommentedEmptyConstructor",
  "PMD.CommentDefaultAccessModifier"
})
class GraalVmConfigReaderTest {
  /** Supplies isolated paths for each test. */
  @TempDir Path tempDir;

  /** Creates a package-visible test instance for JUnit. */
  GraalVmConfigReaderTest() {}

  @Test
  void readsDescriptorNamesIntoNormalizedTrace() throws IOException {
    final Path config = tempDir.resolve("reflect-config.json");
    Files.writeString(
        config,
        "[{\"name\":\"org.example.Widget\",\"allDeclaredMethods\":true},"
            + "{\"name\":\"org.example.Other\"}]");

    final TraceData result = new GraalVmConfigReader().read(config);

    assertThat(result.loadedClassesDotFormat())
        .containsExactlyInAnyOrder("org.example.Widget", "org.example.Other");
    assertThat(result.loadedClassesSlashFormat()).contains("org/example/Widget");
  }

  @Test
  void rejectsMalformedOrUnsupportedConfigurations() throws IOException {
    final Path malformed = tempDir.resolve("malformed.json");
    final Path invalidName = tempDir.resolve("invalid-name.json");
    final Path trailingRoot = tempDir.resolve("trailing.json");
    final Path malformedArray = tempDir.resolve("malformed-array.json");
    final Path duplicateName = tempDir.resolve("duplicate.json");
    Files.writeString(malformed, "[{\"name\":42}]");
    Files.writeString(invalidName, "[{\"name\":\"not a class\"}]");
    Files.writeString(trailingRoot, "[{\"name\":\"org.example.Valid\"}] []");
    Files.writeString(malformedArray, "[{\"name\":\"invalid..name[]\"}]");
    Files.writeString(
        duplicateName, "[{\"name\":\"org.example.First\",\"name\":\"org.example.Second\"}]");
    final GraalVmConfigReader reader = new GraalVmConfigReader();

    assertThatIOException().isThrownBy(() -> reader.read(malformed));
    assertThatIOException().isThrownBy(() -> reader.read(invalidName));
    assertThatIOException().isThrownBy(() -> reader.read(trailingRoot));
    assertThatIOException().isThrownBy(() -> reader.read(malformedArray));
    assertThatIOException().isThrownBy(() -> reader.read(duplicateName));
    assertThatIOException().isThrownBy(() -> reader.read(tempDir.resolve("classes.log")));
  }

  @Test
  void extractsArrayDescriptorsAndSourceArraysIntoComponentClasses() throws IOException {
    final Path config = tempDir.resolve("array-reflect-config.json");
    Files.writeString(
        config,
        "[\n"
            + "  {\"name\": \"kotlin.internal.jdk8.JDK8PlatformImplementations\"},\n"
            + "  {\"name\": \"kotlin.KotlinVersion\"},\n"
            + "  {\"name\": \"kotlin.KotlinVersion[]\"},\n"
            + "  {\"name\": \"kotlin.KotlinVersion$Companion\"},\n"
            + "  {\"name\": \"kotlin.KotlinVersion$Companion[]\"},\n"
            + "  {\"name\": \"[Lorg.example.Widget;\"},\n"
            + "  {\"name\": \"int[]\"},\n"
            + "  {\"name\": \"[B\"}\n"
            + "]");

    final TraceData result = new GraalVmConfigReader().read(config);

    assertThat(result.loadedClassesDotFormat())
        .containsExactlyInAnyOrder(
            "kotlin.internal.jdk8.JDK8PlatformImplementations",
            "kotlin.KotlinVersion",
            "kotlin.KotlinVersion$Companion",
            "org.example.Widget");
  }

  @Test
  void extractsRootsFromUnifiedReachabilityMetadata() throws IOException {
    final Path config = tempDir.resolve("reachability-metadata.json");
    Files.writeString(
        config,
        "{\n"
            + "  \"reflection\": [\n"
            + "    {\"type\": \"boolean\"},\n"
            + "    {\"type\": \"byte[]\"},\n"
            + "    {\"type\": \"com.fasterxml.jackson.core.Versioned\"},\n"
            + "    {\"type\": \"com.fasterxml.jackson.databind.deser."
            + "BeanDeserializerModifier[]\"}\n"
            + "  ],\n"
            + "  \"serialization\": [\n"
            + "    {\"type\": \"org.example.SerializablePayload\"}\n"
            + "  ],\n"
            + "  \"jni\": [\n"
            + "    {\"name\": \"org.example.NativeLibraryBridge\"}\n"
            + "  ]\n"
            + "}");

    final TraceData result = new GraalVmConfigReader().read(config);

    assertThat(result.loadedClassesDotFormat())
        .containsExactlyInAnyOrder(
            "com.fasterxml.jackson.core.Versioned",
            "com.fasterxml.jackson.databind.deser.BeanDeserializerModifier",
            "org.example.SerializablePayload",
            "org.example.NativeLibraryBridge");
  }

  @Test
  void propagatesUnreadableFiles() {
    final Path missing = tempDir.resolve("missing.json");

    assertThatIOException().isThrownBy(() -> new GraalVmConfigReader().read(missing));
  }
}
