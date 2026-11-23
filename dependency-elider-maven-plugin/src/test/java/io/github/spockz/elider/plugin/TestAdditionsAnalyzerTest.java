/* WHY: Proves compiled test roots restore only needed classes through full program-body closure. */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;

import io.github.spockz.elider.trimmer.ClosureQueryPolicy;
import io.github.spockz.elider.trimmer.JdkApiClassTableReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Label;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import proguard.classfile.ClassPool;

/** Exercises closure and the generated runtime archive. */
@SuppressWarnings({
  "PMD.AtLeastOneConstructor",
  "PMD.CommentRequired",
  "PMD.CommentDefaultAccessModifier",
  "PMD.UseConcurrentHashMap",
  "PMD.AvoidInstantiatingObjectsInLoops",
  "PMD.TooManyMethods",
  "PMD.AvoidDuplicateLiterals",
  "PMD.LawOfDemeter"
})
final class TestAdditionsAnalyzerTest {
  private static final String BUILDER = "lib/Builder";
  private static final String VOID_METHOD = "()V";

  @TempDir private Path directory;

  @Test
  void restoresMethodBodyChainAcrossDroppedArtifactWithoutDuplicatingProduction() throws Exception {
    final Fixture fixture = fixture();
    final Path output = directory.resolve("test-additions.jar");
    final TestAdditionsAnalyzer.Result first = fixture.prepare(output);
    final byte[] bytes = Files.readAllBytes(output);
    final TestAdditionsAnalyzer.Result second = fixture.prepare(output);
    assertAll(
        "compiled test roots and transitive program bodies",
        () -> assertThat(first.additionsJar()).contains(output),
        () ->
            assertThat(first.addedClassesByArtifact())
                .containsEntry("library", Set.of(BUILDER, "lib/Helper"))
                .containsEntry("dropped", Set.of("drop/Marker", "drop/Deep")),
        () ->
            assertThat(jarEntries(output))
                .containsExactlyInAnyOrder(
                    "lib/Builder.class",
                    "lib/Helper.class",
                    "drop/Marker.class",
                    "drop/Deep.class"),
        () -> assertThat(Files.readAllBytes(output)).isEqualTo(bytes),
        () -> assertThat(second).isEqualTo(first),
        () -> assertThat(first.conservativeFallbackUsed()).isFalse());
  }

  @Test
  void closesTestUseOfRetainedProductionClassOverItsRemovedMethodDependencies() throws Exception {
    final Fixture fixture = fixture();
    Files.delete(fixture.tests().resolve("test/UsesBuilder.class"));
    Files.write(
        fixture.tests().resolve("test/UsesClient.class"),
        classBytes("test/UsesClient", "lib/Client"));
    final byte[] client = classBytes("lib/Client", "lib/Helper");
    final Path original = directory.resolve("library.jar");
    final Map<String, byte[]> originalEntries = new HashMap<>(jarEntriesWithBytes(original));
    originalEntries.put("lib/Client.class", client);
    writeJar(original, originalEntries);
    writeJar(directory.resolve("effective.jar"), Map.of("lib/Client.class", client));

    final Path output = directory.resolve("retained-client-additions.jar");
    final TestAdditionsAnalyzer.Result result = fixture.prepare(output);

    assertAll(
        "a class retained for production can call a helper removed from its JAR",
        () -> assertThat(result.additionsJar()).contains(output),
        () -> assertThat(result.addedClassesByArtifact().get("library")).contains("lib/Helper"),
        () -> assertThat(result.addedClassesByArtifact().get("dropped")).contains("drop/Marker"),
        () -> assertThat(jarEntries(output)).doesNotContain("lib/Client.class"));
  }

  @Test
  void usesUnchangedResourcesFromTheRetainedProductionArtifact() throws Exception {
    final Fixture fixture = fixture();
    final Path original = directory.resolve("library.jar");
    final Path effective = directory.resolve("effective.jar");
    final byte[] resource = "test setting\n".getBytes(java.nio.charset.StandardCharsets.UTF_8);
    final Map<String, byte[]> originalEntries = new HashMap<>(jarEntriesWithBytes(original));
    originalEntries.put("config/test.properties", resource);
    writeJar(original, originalEntries);
    final Map<String, byte[]> effectiveEntries = new HashMap<>(jarEntriesWithBytes(effective));
    effectiveEntries.put("config/test.properties", resource);
    writeJar(effective, effectiveEntries);

    final Path output = directory.resolve("test-additions.jar");
    final TestAdditionsAnalyzer.Result result = fixture.prepare(output);

    assertAll(
        "the production artifact already supplies the original resource to tests",
        () -> assertThat(result.additionsJar()).contains(output),
        () -> assertThat(jarEntries(output)).doesNotContain("config/test.properties"),
        () -> assertThat(jarEntries(effective)).contains("config/test.properties"),
        () -> assertThat(result.addedClassesByArtifact().get("library")).contains(BUILDER));
  }

  @Test
  void rejectsResourcesInAnArtifactThatWouldContributeClasses() throws Exception {
    final Fixture fixture = fixture();
    final Path original = directory.resolve("library.jar");
    final Map<String, byte[]> originalEntries = jarEntriesWithBytes(original);
    final Map<String, byte[]> withResource = new HashMap<>(originalEntries);
    withResource.put("config/test.properties", new byte[] {1});
    writeJar(original, withResource);
    assertThatThrownBy(() -> fixture.prepare(directory.resolve("unsafe.jar")))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("resource");
  }

  @Test
  void rejectsServiceDescriptorsInContributingArtifact() throws Exception {
    final Fixture fixture = fixture();
    final Path original = directory.resolve("library.jar");
    final Map<String, byte[]> withService = new HashMap<>(jarEntriesWithBytes(original));
    withService.put(
        "META-INF/services/lib.Service",
        "lib.Builder\n".getBytes(java.nio.charset.StandardCharsets.UTF_8));
    writeJar(original, withService);
    assertThatThrownBy(() -> fixture.prepare(directory.resolve("service-unsafe.jar")))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("META-INF/services/lib.Service");
  }

  @Test
  void rejectsServiceOnlyRootsInDroppedArtifact() throws Exception {
    final Fixture fixture = fixture();
    final Path service = directory.resolve("service-only.jar");
    writeJar(
        service,
        Map.of(
            "META-INF/services/java.lang.Runnable",
            "service.Only\n".getBytes(java.nio.charset.StandardCharsets.UTF_8),
            "service/Only.class",
            classBytes("service/Only", null)));
    final List<TestAdditionsAnalyzer.ArtifactInput> originals =
        new java.util.ArrayList<>(fixture.originals());
    originals.add(
        new TestAdditionsAnalyzer.ArtifactInput("service-only", service, Optional.empty(), true));
    assertThatThrownBy(
            () ->
                TestAdditionsAnalyzer.prepare(
                    fixture.tests(),
                    fixture.main(),
                    originals,
                    directory.resolve("service-only-unsafe.jar"),
                    new JdkApiClassTableReader().readFrozen(),
                    ClosureQueryPolicy.conservative()))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("service-only")
        .hasMessageContaining("META-INF/services/java.lang.Runnable");
  }

  @Test
  void rejectsChangedServiceResourcesInAnOtherwiseUnneededRetainedArtifact() throws Exception {
    final Fixture fixture = fixture();
    final Path original = directory.resolve("service-original.jar");
    final Path effective = directory.resolve("service-effective.jar");
    final byte[] provider = classBytes("service/Only", null);
    writeJar(
        original,
        Map.of(
            "META-INF/services/java.lang.Runnable",
            "service.Only\n".getBytes(java.nio.charset.StandardCharsets.UTF_8),
            "service/Only.class",
            provider));
    writeJar(effective, Map.of("service/Only.class", provider));
    final List<TestAdditionsAnalyzer.ArtifactInput> originals =
        new java.util.ArrayList<>(fixture.originals());
    originals.add(
        new TestAdditionsAnalyzer.ArtifactInput(
            "changed-service", original, Optional.of(effective), true));
    assertThatThrownBy(
            () ->
                TestAdditionsAnalyzer.prepare(
                    fixture.tests(),
                    fixture.main(),
                    originals,
                    directory.resolve("changed-service-unsafe.jar"),
                    new JdkApiClassTableReader().readFrozen(),
                    ClosureQueryPolicy.conservative()))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("changed-service")
        .hasMessageContaining("META-INF/services/java.lang.Runnable");
  }

  @Test
  void rejectsUnchangedServiceDescriptorWhoseProviderWasTrimmed() throws Exception {
    final Fixture fixture = fixture();
    final Path original = directory.resolve("service-provider-original.jar");
    final Path effective = directory.resolve("service-provider-effective.jar");
    final byte[] descriptor = "service.Only\n".getBytes(java.nio.charset.StandardCharsets.UTF_8);
    writeJar(
        original,
        Map.of(
            "META-INF/services/java.lang.Runnable",
            descriptor,
            "service/Only.class",
            classBytes("service/Only", null)));
    writeJar(effective, Map.of("META-INF/services/java.lang.Runnable", descriptor));
    final List<TestAdditionsAnalyzer.ArtifactInput> originals =
        new java.util.ArrayList<>(fixture.originals());
    originals.add(
        new TestAdditionsAnalyzer.ArtifactInput(
            "trimmed-service-provider", original, Optional.of(effective), true));
    assertThatThrownBy(
            () ->
                TestAdditionsAnalyzer.prepare(
                    fixture.tests(),
                    fixture.main(),
                    originals,
                    directory.resolve("trimmed-service-unsafe.jar"),
                    new JdkApiClassTableReader().readFrozen(),
                    ClosureQueryPolicy.conservative()))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("trimmed-service-provider")
        .hasMessageContaining("META-INF/services/java.lang.Runnable");
  }

  @Test
  void rejectsChangedOpaqueResourceInTrimmedArtifact() throws Exception {
    final Fixture fixture = fixture();
    final Path original = directory.resolve("opaque-original.jar");
    final Path effective = directory.resolve("opaque-effective.jar");
    final byte[] resource = "lib.Unused\n".getBytes(java.nio.charset.StandardCharsets.UTF_8);
    writeJar(
        original,
        Map.of(
            "config/provider-name.txt",
            resource,
            "opaque/Entry.class",
            classBytes("opaque/Entry", null)));
    writeJar(
        effective,
        Map.of(
            "config/provider-name.txt",
            "other\n".getBytes(java.nio.charset.StandardCharsets.UTF_8)));
    final List<TestAdditionsAnalyzer.ArtifactInput> originals =
        new java.util.ArrayList<>(fixture.originals());
    originals.add(
        new TestAdditionsAnalyzer.ArtifactInput(
            "opaque-resource", original, Optional.of(effective), true));
    assertThatThrownBy(
            () ->
                TestAdditionsAnalyzer.prepare(
                    fixture.tests(),
                    fixture.main(),
                    originals,
                    directory.resolve("opaque-unsafe.jar"),
                    new JdkApiClassTableReader().readFrozen(),
                    ClosureQueryPolicy.conservative()))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("opaque-resource")
        .hasMessageContaining("config/provider-name.txt");
  }

  @Test
  void restoresLiteralReflectiveClassNamedByCompiledTest() throws Exception {
    final Fixture fixture = fixture();
    Files.write(
        fixture.tests().resolve("test/Reflective.class"),
        reflectiveClassBytes("test/Reflective", "lib.Unused"));
    final Path output = directory.resolve("reflective-test-additions.jar");
    final TestAdditionsAnalyzer.Result result = fixture.prepare(output);
    assertAll(
        () -> assertThat(result.addedClassesByArtifact().get("library")).contains("lib/Unused"),
        () -> assertThat(jarEntries(output)).contains("lib/Unused.class"));
  }

  @Test
  void restoresLiteralReflectiveClassNamedByReachedOriginalBody() throws Exception {
    final Fixture fixture = fixture();
    final Path original = directory.resolve("library.jar");
    final Map<String, byte[]> entries = new HashMap<>(jarEntriesWithBytes(original));
    entries.put("lib/Builder.class", reflectiveClassBytes(BUILDER, "lib.Unused"));
    writeJar(original, entries);
    final Path output = directory.resolve("reflective-library-additions.jar");
    final TestAdditionsAnalyzer.Result result = fixture.prepare(output);
    assertAll(
        () ->
            assertThat(result.addedClassesByArtifact().get("library"))
                .contains(BUILDER, "lib/Unused"),
        () -> assertThat(jarEntries(output)).contains("lib/Unused.class"));
  }

  @Test
  void unresolvedReflectiveLoadInCompiledTestsUsesConservativeClassFallback() throws Exception {
    final Fixture fixture = fixture();
    Files.write(
        fixture.tests().resolve("test/ReflectiveVariable.class"),
        variableReflectiveClassBytes("test/ReflectiveVariable"));
    final TestAdditionsAnalyzer.Result result =
        fixture.prepare(directory.resolve("variable-test-additions.jar"));
    assertAll(
        () -> assertThat(result.conservativeFallbackUsed()).isTrue(),
        () ->
            assertThat(result.addedClassesByArtifact())
                .containsEntry("library", Set.of(BUILDER, "lib/Helper", "lib/Unused"))
                .containsEntry("dropped", Set.of("drop/Marker", "drop/Deep", "drop/Unused")));
  }

  @Test
  void conditionalReflectiveNamesUseConservativeFallbackForBothBranches() throws Exception {
    final Fixture fixture = fixture();
    Files.write(
        fixture.tests().resolve("test/ConditionalReflection.class"),
        conditionalReflectiveClassBytes());

    final TestAdditionsAnalyzer.Result result =
        fixture.prepare(directory.resolve("conditional-reflection-additions.jar"));

    assertAll(
        "branch-specific class names cannot be narrowed to the last visited literal",
        () -> assertThat(result.conservativeFallbackUsed()).isTrue(),
        () -> assertThat(result.addedClassesByArtifact().get("library")).contains("lib/Unused"),
        () -> assertThat(result.addedClassesByArtifact().get("dropped")).contains("drop/Unused"));
  }

  @Test
  void unresolvedReflectiveLoadInReachedOriginalBodyUsesConservativeClassFallback()
      throws Exception {
    final Fixture fixture = fixture();
    final Path original = directory.resolve("library.jar");
    final Map<String, byte[]> entries = new HashMap<>(jarEntriesWithBytes(original));
    entries.put("lib/Builder.class", variableReflectiveClassBytes(BUILDER));
    writeJar(original, entries);
    final TestAdditionsAnalyzer.Result result =
        fixture.prepare(directory.resolve("variable-library-additions.jar"));
    assertAll(
        () -> assertThat(result.conservativeFallbackUsed()).isTrue(),
        () ->
            assertThat(result.addedClassesByArtifact())
                .containsEntry("library", Set.of(BUILDER, "lib/Helper", "lib/Unused"))
                .containsEntry("dropped", Set.of("drop/Marker", "drop/Deep", "drop/Unused")));
  }

  @Test
  void serviceLoaderCallInCompiledTestRestoresProvidersNamedByUnchangedDescriptor()
      throws Exception {
    final Fixture fixture = fixture();
    Files.write(
        fixture.tests().resolve("test/UsesServiceLoader.class"),
        serviceLoaderClassBytes("test/UsesServiceLoader"));
    final Path serviceLibrary = directory.resolve("unchanged-service-descriptor.jar");
    writeJar(
        serviceLibrary,
        Map.of(
            "META-INF/services/java.lang.Runnable",
            "drop.Marker\n".getBytes(java.nio.charset.StandardCharsets.UTF_8)));
    final List<TestAdditionsAnalyzer.ArtifactInput> originals =
        new java.util.ArrayList<>(fixture.originals());
    originals.add(
        new TestAdditionsAnalyzer.ArtifactInput(
            "unchanged-service-descriptor", serviceLibrary, Optional.of(serviceLibrary), true));
    final TestAdditionsAnalyzer.Result result =
        TestAdditionsAnalyzer.prepare(
            fixture.tests(),
            fixture.main(),
            originals,
            directory.resolve("service-loader-additions.jar"),
            new JdkApiClassTableReader().readFrozen(),
            ClosureQueryPolicy.conservative());
    assertAll(
        () -> assertThat(result.conservativeFallbackUsed()).isTrue(),
        () ->
            assertThat(result.addedClassesByArtifact().get("dropped"))
                .contains("drop/Marker", "drop/Unused"));
  }

  @Test
  void serviceLoaderCallInReachedOriginalBodyUsesConservativeClassFallback() throws Exception {
    final Fixture fixture = fixture();
    final Path original = directory.resolve("library.jar");
    final Map<String, byte[]> entries = new HashMap<>(jarEntriesWithBytes(original));
    entries.put("lib/Builder.class", serviceLoaderClassBytes(BUILDER));
    writeJar(original, entries);
    final TestAdditionsAnalyzer.Result result =
        fixture.prepare(directory.resolve("service-loader-body-additions.jar"));
    assertAll(
        () -> assertThat(result.conservativeFallbackUsed()).isTrue(),
        () ->
            assertThat(result.addedClassesByArtifact().get("library"))
                .contains(BUILDER, "lib/Unused"),
        () -> assertThat(result.addedClassesByArtifact().get("dropped")).contains("drop/Unused"));
  }

  @Test
  void permitsUnresolvedReflectionInAnUnchangedOrdinaryTestDependency() throws Exception {
    final Fixture fixture = fixture();
    final Path library = directory.resolve("unchanged-test-library.jar");
    writeJar(
        library,
        Map.of(
            "testlib/ReflectionUtils.class",
            variableReflectiveClassBytes("testlib/ReflectionUtils")));
    Files.write(
        fixture.tests().resolve("test/UsesReflectionUtils.class"),
        classBytes("test/UsesReflectionUtils", "testlib/ReflectionUtils"));
    final List<TestAdditionsAnalyzer.ArtifactInput> originals =
        new java.util.ArrayList<>(fixture.originals());
    originals.add(
        new TestAdditionsAnalyzer.ArtifactInput(
            "unchanged-test-library", library, Optional.of(library), true));
    final TestAdditionsAnalyzer.Result result =
        TestAdditionsAnalyzer.prepare(
            fixture.tests(),
            fixture.main(),
            originals,
            directory.resolve("unchanged-library-additions.jar"),
            new JdkApiClassTableReader().readFrozen(),
            ClosureQueryPolicy.conservative());
    assertAll(
        () ->
            assertThat(result.addedClassesByArtifact())
                .containsEntry("library", Set.of(BUILDER, "lib/Helper", "lib/Unused"))
                .containsEntry("dropped", Set.of("drop/Marker", "drop/Deep", "drop/Unused")),
        () ->
            assertThat(result.addedClassesByArtifact()).doesNotContainKey("unchanged-test-library"),
        () -> assertThat(result.conservativeFallbackUsed()).isTrue(),
        () ->
            assertThat(jarEntries(result.additionsJar().orElseThrow()))
                .contains("lib/Unused.class", "drop/Unused.class"));
  }

  @Test
  void unresolvedReflectionRejectsAnUnsafeNewlySeededMultiReleaseContributor() throws Exception {
    final Fixture fixture = fixture();
    final Path library = directory.resolve("unchanged-reflective-library.jar");
    writeJar(
        library,
        Map.of(
            "testlib/ReflectionUtils.class",
            variableReflectiveClassBytes("testlib/ReflectionUtils")));
    Files.write(
        fixture.tests().resolve("test/UsesReflectionUtils.class"),
        classBytes("test/UsesReflectionUtils", "testlib/ReflectionUtils"));
    final Path multiRelease = directory.resolve("fallback-multi-release.jar");
    final java.util.jar.Manifest manifest = new java.util.jar.Manifest();
    manifest.getMainAttributes().putValue("Manifest-Version", "1.0");
    manifest.getMainAttributes().putValue("Multi-Release", "true");
    try (JarOutputStream output =
        new JarOutputStream(Files.newOutputStream(multiRelease), manifest)) {
      final JarEntry entry = new JarEntry("mr/Unused.class");
      output.putNextEntry(entry);
      output.write(classBytes("mr/Unused", null));
      output.closeEntry();
      final JarEntry versioned = new JarEntry("META-INF/versions/9/mr/Unused.class");
      output.putNextEntry(versioned);
      output.write(classBytes("mr/Unused", null));
      output.closeEntry();
    }
    final List<TestAdditionsAnalyzer.ArtifactInput> originals =
        new java.util.ArrayList<>(fixture.originals());
    originals.add(
        new TestAdditionsAnalyzer.ArtifactInput(
            "unchanged-reflective", library, Optional.of(library), true));
    originals.add(
        new TestAdditionsAnalyzer.ArtifactInput("unsafe-mr", multiRelease, Optional.empty(), true));
    assertThatThrownBy(
            () ->
                TestAdditionsAnalyzer.prepare(
                    fixture.tests(),
                    fixture.main(),
                    originals,
                    directory.resolve("fallback-unsafe.jar"),
                    new JdkApiClassTableReader().readFrozen(),
                    ClosureQueryPolicy.conservative()))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("multi-release")
        .hasMessageContaining("unsafe-mr");
  }

  @Test
  void rejectsDuplicateOriginalClassProviders() throws Exception {
    final Fixture fixture = fixture();
    final Path duplicate = directory.resolve("duplicate.jar");
    writeJar(duplicate, Map.of("lib/Builder.class", classBytes(BUILDER, null)));
    final List<TestAdditionsAnalyzer.ArtifactInput> originals =
        new java.util.ArrayList<>(fixture.originals());
    originals.add(
        new TestAdditionsAnalyzer.ArtifactInput(
            "duplicate", duplicate, Optional.of(duplicate), true));
    assertThatThrownBy(
            () ->
                TestAdditionsAnalyzer.prepare(
                    fixture.tests(),
                    fixture.main(),
                    originals,
                    directory.resolve("duplicate-unsafe.jar"),
                    new JdkApiClassTableReader().readFrozen(),
                    ClosureQueryPolicy.conservative()))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("Duplicate original test class provider")
        .hasMessageContaining(BUILDER);
  }

  @Test
  void followsReferencedOrdinaryTestDependencyBodyIntoTrimmedProduction() throws Exception {
    final Fixture fixture = fixture();
    final Path tests = fixture.tests();
    Files.write(
        tests.resolve("test/UsesBuilder.class"), classBytes("test/UsesBuilder", "testlib/Entry"));
    final Path testLibrary = directory.resolve("test-library.jar");
    writeJar(testLibrary, Map.of("testlib/Entry.class", classBytes("testlib/Entry", BUILDER)));
    final List<TestAdditionsAnalyzer.ArtifactInput> inputs =
        new java.util.ArrayList<>(fixture.originals());
    inputs.add(
        new TestAdditionsAnalyzer.ArtifactInput(
            "test-library", testLibrary, Optional.of(testLibrary), true));
    final Path output = directory.resolve("test-additions.jar");
    final TestAdditionsAnalyzer.Result result =
        TestAdditionsAnalyzer.prepare(
            tests,
            fixture.main(),
            inputs,
            output,
            new JdkApiClassTableReader().readFrozen(),
            ClosureQueryPolicy.conservative());
    assertAll(
        "ordinary test dependency method body reaches removed production classes",
        () -> assertThat(result.addedClassesByArtifact()).containsKeys("library", "dropped"),
        () -> assertThat(result.addedClassesByArtifact()).doesNotContainKey("test-library"),
        () -> assertThat(jarEntries(output)).doesNotContain("testlib/Entry.class"));
  }

  @Test
  void unneededMultiReleaseTestLibraryDoesNotBlockOtherAdditions() throws Exception {
    final Fixture fixture = fixture();
    final Path multiRelease = directory.resolve("multi-release-test-library.jar");
    final java.util.jar.Manifest manifest = new java.util.jar.Manifest();
    manifest.getMainAttributes().putValue("Manifest-Version", "1.0");
    manifest.getMainAttributes().putValue("Multi-Release", "true");
    try (JarOutputStream output =
        new JarOutputStream(Files.newOutputStream(multiRelease), manifest)) {
      final JarEntry base = new JarEntry("other/Unused.class");
      output.putNextEntry(base);
      output.write(classBytes("other/Unused", null));
      output.closeEntry();
      final JarEntry versioned = new JarEntry("META-INF/versions/9/other/Unused.class");
      output.putNextEntry(versioned);
      output.write(classBytes("other/Unused", null));
      output.closeEntry();
    }
    final List<TestAdditionsAnalyzer.ArtifactInput> inputs =
        new java.util.ArrayList<>(fixture.originals());
    inputs.add(
        new TestAdditionsAnalyzer.ArtifactInput(
            "unneeded-mr", multiRelease, Optional.of(multiRelease), true));
    final Path output = directory.resolve("test-additions.jar");
    final TestAdditionsAnalyzer.Result result =
        TestAdditionsAnalyzer.prepare(
            fixture.tests(),
            fixture.main(),
            inputs,
            output,
            new JdkApiClassTableReader().readFrozen(),
            ClosureQueryPolicy.conservative());
    assertAll(
        () -> assertThat(result.additionsJar()).contains(output),
        () -> assertThat(result.addedClassesByArtifact()).doesNotContainKey("unneeded-mr"),
        () -> assertThat(jarEntries(output)).contains("lib/Builder.class", "drop/Marker.class"));
  }

  @Test
  void versionedOnlyClassInOrdinaryTestLibraryHasItsRuntimeOwner() throws Exception {
    final Fixture fixture = fixture();
    final Path testClasses = fixture.tests();
    Files.write(
        testClasses.resolve("test/UsesEntry.class"), classBytes("test/UsesEntry", "other/Entry"));
    final Path multiRelease = directory.resolve("versioned-test-library.jar");
    final java.util.jar.Manifest manifest = new java.util.jar.Manifest();
    manifest.getMainAttributes().putValue("Manifest-Version", "1.0");
    manifest.getMainAttributes().putValue("Multi-Release", "true");
    try (JarOutputStream output =
        new JarOutputStream(Files.newOutputStream(multiRelease), manifest)) {
      final JarEntry base = new JarEntry("other/Entry.class");
      output.putNextEntry(base);
      output.write(classBytes("other/Entry", "other/VersionedOnly"));
      output.closeEntry();
      final JarEntry versioned = new JarEntry("META-INF/versions/9/other/VersionedOnly.class");
      output.putNextEntry(versioned);
      output.write(classBytes("other/VersionedOnly", null));
      output.closeEntry();
    }
    final List<TestAdditionsAnalyzer.ArtifactInput> inputs =
        new java.util.ArrayList<>(fixture.originals());
    inputs.add(
        new TestAdditionsAnalyzer.ArtifactInput(
            "versioned-test-library", multiRelease, Optional.of(multiRelease), true));
    final Path output = directory.resolve("test-additions.jar");
    final TestAdditionsAnalyzer.Result result =
        TestAdditionsAnalyzer.prepare(
            testClasses,
            fixture.main(),
            inputs,
            output,
            new JdkApiClassTableReader().readFrozen(),
            ClosureQueryPolicy.conservative());
    assertAll(
        "the selected runtime view supplies versioned-only classes",
        () -> assertThat(result.additionsJar()).contains(output),
        () ->
            assertThat(result.addedClassesByArtifact()).doesNotContainKey("versioned-test-library"),
        () -> assertThat(jarEntries(output)).contains("lib/Builder.class"));
  }

  @Test
  void absentCurrentTestOutputDoesNotPublishStaleAdditions() throws Exception {
    final Fixture fixture = fixture();
    final Path output = directory.resolve("test-additions.jar");
    Files.write(output, new byte[] {1});
    final TestAdditionsAnalyzer.Result result =
        TestAdditionsAnalyzer.prepare(
            directory.resolve("absent-test-classes"),
            fixture.main(),
            fixture.originals(),
            output,
            new JdkApiClassTableReader().readFrozen(),
            ClosureQueryPolicy.conservative());
    assertAll(
        () -> assertThat(result.additionsJar()).isEmpty(), () -> assertThat(output).doesNotExist());
  }

  private Fixture fixture() throws IOException {
    final Path tests = Files.createDirectories(directory.resolve("test-classes"));
    final Path main = Files.createDirectories(directory.resolve("classes"));
    Files.createDirectories(tests.resolve("test"));
    Files.write(tests.resolve("test/UsesBuilder.class"), classBytes("test/UsesBuilder", BUILDER));
    final Path original = directory.resolve("library.jar");
    final Path effective = directory.resolve("effective.jar");
    final Path dropped = directory.resolve("dropped.jar");
    writeJar(
        original,
        Map.of(
            "lib/Client.class", classBytes("lib/Client", null),
            "lib/Builder.class", classBytes(BUILDER, "lib/Helper"),
            "lib/Helper.class", classBytes("lib/Helper", "drop/Marker"),
            "lib/Unused.class", classBytes("lib/Unused", null)));
    writeJar(effective, Map.of("lib/Client.class", classBytes("lib/Client", null)));
    writeJar(
        dropped,
        Map.of(
            "drop/Marker.class", classBytes("drop/Marker", "drop/Deep"),
            "drop/Deep.class", classBytes("drop/Deep", null),
            "drop/Unused.class", classBytes("drop/Unused", null)));
    return new Fixture(
        tests,
        main,
        List.of(
            new TestAdditionsAnalyzer.ArtifactInput("library", original, Optional.of(effective)),
            new TestAdditionsAnalyzer.ArtifactInput("dropped", dropped, Optional.empty())));
  }

  private static byte[] classBytes(final String name, final String referenced) {
    final ClassWriter writer = new ClassWriter(0);
    writer.visit(Opcodes.V21, Opcodes.ACC_PUBLIC, name, null, "java/lang/Object", null);
    final MethodVisitor constructor =
        writer.visitMethod(Opcodes.ACC_PUBLIC, "<init>", VOID_METHOD, null, null);
    constructor.visitCode();
    constructor.visitVarInsn(Opcodes.ALOAD, 0);
    constructor.visitMethodInsn(
        Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", VOID_METHOD, false);
    constructor.visitInsn(Opcodes.RETURN);
    constructor.visitMaxs(1, 1);
    constructor.visitEnd();
    if (referenced != null) {
      final MethodVisitor method =
          writer.visitMethod(Opcodes.ACC_PUBLIC, "run", VOID_METHOD, null, null);
      method.visitCode();
      method.visitTypeInsn(Opcodes.NEW, referenced);
      method.visitInsn(Opcodes.DUP);
      method.visitMethodInsn(Opcodes.INVOKESPECIAL, referenced, "<init>", VOID_METHOD, false);
      method.visitInsn(Opcodes.POP);
      method.visitInsn(Opcodes.RETURN);
      method.visitMaxs(2, 1);
      method.visitEnd();
    }
    writer.visitEnd();
    return writer.toByteArray();
  }

  private static byte[] reflectiveClassBytes(final String name, final String target) {
    final ClassWriter writer = new ClassWriter(0);
    writer.visit(Opcodes.V21, Opcodes.ACC_PUBLIC, name, null, "java/lang/Object", null);
    final MethodVisitor constructor =
        writer.visitMethod(Opcodes.ACC_PUBLIC, "<init>", VOID_METHOD, null, null);
    constructor.visitCode();
    constructor.visitVarInsn(Opcodes.ALOAD, 0);
    constructor.visitMethodInsn(
        Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", VOID_METHOD, false);
    constructor.visitInsn(Opcodes.RETURN);
    constructor.visitMaxs(1, 1);
    constructor.visitEnd();
    final MethodVisitor method =
        writer.visitMethod(Opcodes.ACC_PUBLIC, "run", VOID_METHOD, null, null);
    method.visitCode();
    method.visitLdcInsn(target);
    method.visitMethodInsn(
        Opcodes.INVOKESTATIC,
        "java/lang/Class",
        "forName",
        "(Ljava/lang/String;)Ljava/lang/Class;",
        false);
    method.visitInsn(Opcodes.POP);
    method.visitInsn(Opcodes.RETURN);
    method.visitMaxs(1, 1);
    method.visitEnd();
    writer.visitEnd();
    return writer.toByteArray();
  }

  private static byte[] variableReflectiveClassBytes(final String name) {
    final ClassWriter writer = new ClassWriter(0);
    writer.visit(Opcodes.V21, Opcodes.ACC_PUBLIC, name, null, "java/lang/Object", null);
    final MethodVisitor constructor =
        writer.visitMethod(Opcodes.ACC_PUBLIC, "<init>", VOID_METHOD, null, null);
    constructor.visitCode();
    constructor.visitVarInsn(Opcodes.ALOAD, 0);
    constructor.visitMethodInsn(
        Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", VOID_METHOD, false);
    constructor.visitInsn(Opcodes.RETURN);
    constructor.visitMaxs(1, 1);
    constructor.visitEnd();
    final MethodVisitor method =
        writer.visitMethod(Opcodes.ACC_PUBLIC, "run", "(Ljava/lang/String;)V", null, null);
    method.visitCode();
    method.visitVarInsn(Opcodes.ALOAD, 1);
    method.visitMethodInsn(
        Opcodes.INVOKESTATIC,
        "java/lang/Class",
        "forName",
        "(Ljava/lang/String;)Ljava/lang/Class;",
        false);
    method.visitInsn(Opcodes.POP);
    method.visitInsn(Opcodes.RETURN);
    method.visitMaxs(1, 2);
    method.visitEnd();
    writer.visitEnd();
    return writer.toByteArray();
  }

  private static byte[] conditionalReflectiveClassBytes() {
    final ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_MAXS);
    writer.visit(
        Opcodes.V21,
        Opcodes.ACC_PUBLIC,
        "test/ConditionalReflection",
        null,
        "java/lang/Object",
        null);
    final MethodVisitor method =
        writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "run", "(Z)V", null, null);
    final Label second = new Label();
    final Label merged = new Label();
    method.visitCode();
    method.visitVarInsn(Opcodes.ILOAD, 0);
    method.visitJumpInsn(Opcodes.IFEQ, second);
    method.visitLdcInsn("lib.Unused");
    method.visitJumpInsn(Opcodes.GOTO, merged);
    method.visitLabel(second);
    method.visitLdcInsn("drop.Unused");
    method.visitLabel(merged);
    method.visitMethodInsn(
        Opcodes.INVOKESTATIC,
        "java/lang/Class",
        "forName",
        "(Ljava/lang/String;)Ljava/lang/Class;",
        false);
    method.visitInsn(Opcodes.POP);
    method.visitInsn(Opcodes.RETURN);
    method.visitMaxs(0, 0);
    method.visitEnd();
    writer.visitEnd();
    return writer.toByteArray();
  }

  private static byte[] serviceLoaderClassBytes(final String name) {
    final ClassWriter writer = new ClassWriter(0);
    writer.visit(Opcodes.V21, Opcodes.ACC_PUBLIC, name, null, "java/lang/Object", null);
    final MethodVisitor constructor =
        writer.visitMethod(Opcodes.ACC_PUBLIC, "<init>", VOID_METHOD, null, null);
    constructor.visitCode();
    constructor.visitVarInsn(Opcodes.ALOAD, 0);
    constructor.visitMethodInsn(
        Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", VOID_METHOD, false);
    constructor.visitInsn(Opcodes.RETURN);
    constructor.visitMaxs(1, 1);
    constructor.visitEnd();
    final MethodVisitor method =
        writer.visitMethod(Opcodes.ACC_PUBLIC, "run", VOID_METHOD, null, null);
    method.visitCode();
    method.visitLdcInsn(org.objectweb.asm.Type.getType("Ljava/lang/Runnable;"));
    method.visitMethodInsn(
        Opcodes.INVOKESTATIC,
        "java/util/ServiceLoader",
        "load",
        "(Ljava/lang/Class;)Ljava/util/ServiceLoader;",
        false);
    method.visitInsn(Opcodes.POP);
    method.visitInsn(Opcodes.RETURN);
    method.visitMaxs(1, 1);
    method.visitEnd();
    writer.visitEnd();
    return writer.toByteArray();
  }

  private static void writeJar(final Path output, final Map<String, byte[]> entries)
      throws IOException {
    try (JarOutputStream jar = new JarOutputStream(Files.newOutputStream(output))) {
      for (final Map.Entry<String, byte[]> entry : new java.util.TreeMap<>(entries).entrySet()) {
        final JarEntry jarEntry = new JarEntry(entry.getKey());
        jarEntry.setTime(0L);
        jar.putNextEntry(jarEntry);
        jar.write(entry.getValue());
        jar.closeEntry();
      }
    }
  }

  private static Set<String> jarEntries(final Path path) throws IOException {
    try (JarFile jar = new JarFile(path.toFile())) {
      return jar.stream().map(JarEntry::getName).collect(java.util.stream.Collectors.toSet());
    }
  }

  private static Map<String, byte[]> jarEntriesWithBytes(final Path path) throws IOException {
    try (JarFile jar = new JarFile(path.toFile())) {
      final Map<String, byte[]> entries = new HashMap<>();
      for (final JarEntry entry : jar.stream().toList()) {
        try (java.io.InputStream input = jar.getInputStream(entry)) {
          entries.put(entry.getName(), input.readAllBytes());
        }
      }
      return entries;
    }
  }

  private record Fixture(
      Path tests, Path main, List<TestAdditionsAnalyzer.ArtifactInput> originals) {
    TestAdditionsAnalyzer.Result prepare(final Path output) throws IOException {
      final ClassPool platform = new JdkApiClassTableReader().readFrozen();
      return TestAdditionsAnalyzer.prepare(
          tests, main, originals, output, platform, ClosureQueryPolicy.conservative());
    }
  }
}
