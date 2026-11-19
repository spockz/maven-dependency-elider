/* WHY: Verifies DependencyDynamicRoots reads every physical archive entry when names repeat. */

package io.github.spockz.elider.plugin.nativeimage;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;

/** Exercises duplicate physical ZIP entry handling. */
@SuppressWarnings({"PMD.AtLeastOneConstructor", "PMD.LawOfDemeter", "PMD.AvoidDuplicateLiterals"})
/* package */ final class DependencyDynamicRootsDuplicateEntryTest {
  /** Temporary directory for test archives. */
  @TempDir /* package */ Path temporaryDirectory;

  /* package */
  @Test
  void readsAllDuplicatePhysicalNativeImageDescriptors() throws IOException {
    final Path validDuplicate =
        NativeImageScanContextTestSupport.duplicateEntryJar(
            temporaryDirectory,
            "duplicate-reflect.jar",
            "META-INF/native-image/example/reflect-config.json",
            NativeImageScanContextTestSupport.reflection("example.First"),
            "META-INF/native-image/example/reflect-confix.json",
            NativeImageScanContextTestSupport.reflection("example.Second"));
    final Path duplicateServices =
        NativeImageScanContextTestSupport.duplicateEntryJar(
            temporaryDirectory,
            "duplicate-services.jar",
            "META-INF/services/example.Service",
            "example.FirstImpl\n",
            "META-INF/services/example.Servicx",
            "example.SecondImpl\n");
    final Path duplicateProperties =
        NativeImageScanContextTestSupport.duplicateEntryJar(
            temporaryDirectory,
            "duplicate-props.jar",
            "META-INF/native-image/example/native-image.properties",
            "Args = -H:Class=example.FirstProp\n",
            "META-INF/native-image/example/native-image.propertixs",
            "Args = -H:Class=example.SecondProp\n");

    final DependencyDynamicRoots.RootScan reflectScan = DependencyDynamicRoots.scan(validDuplicate);
    final DependencyDynamicRoots.RootScan serviceScan =
        DependencyDynamicRoots.scan(duplicateServices);
    final DependencyDynamicRoots.RootScan propsScan =
        DependencyDynamicRoots.scan(duplicateProperties);

    assertAll(
        "Duplicate physical metadata entries",
        () ->
            assertThat(reflectScan.roots())
                .containsExactlyInAnyOrder("example.First", "example.Second"),
        () ->
            assertThat(serviceScan.roots())
                .containsExactlyInAnyOrder(
                    "example.Service", "example.FirstImpl", "example.SecondImpl"),
        () ->
            assertThat(propsScan.roots())
                .containsExactlyInAnyOrder("example.FirstProp", "example.SecondProp"));
  }

  /* package */
  @Test
  void rejectsMalformedFirstDuplicateDescriptorInsteadOfSkippingIt() throws IOException {
    final Path malformedFirst =
        NativeImageScanContextTestSupport.duplicateEntryJar(
            temporaryDirectory,
            "malformed-first-reflect.jar",
            "META-INF/native-image/example/reflect-config.json",
            NativeImageScanContextTestSupport.MALFORMED_JSON,
            "META-INF/native-image/example/reflect-confix.json",
            NativeImageScanContextTestSupport.reflection("example.Second"));
    final Path malformedFirstProperties =
        NativeImageScanContextTestSupport.duplicateEntryJar(
            temporaryDirectory,
            "malformed-first-props.jar",
            "META-INF/native-image/example/native-image.properties",
            "InvalidKey = value\n",
            "META-INF/native-image/example/native-image.propertixs",
            "Args = -H:ClassInitialization=example.SecondProp:build_time\n");

    assertAll(
        "Malformed first duplicate descriptors",
        () ->
            assertThatThrownBy(() -> DependencyDynamicRoots.scan(malformedFirst))
                .isInstanceOf(IOException.class),
        () ->
            assertThatThrownBy(() -> DependencyDynamicRoots.scan(malformedFirstProperties))
                .isInstanceOf(IOException.class));
  }

  /* package */
  @Test
  void scopesExclusionsPerPhysicalResourceDescriptorAcrossDirectAndPointerReads()
      throws IOException {
    final Path provider = validClassJar("provider.jar", "example/Required");
    final String includeRequired =
        """
        {"resources":{"includes":[{"pattern":"example/Required[.]class"}]}}
        """;
    final String excludeRequired =
        """
        {"resources":{"includes":[{"pattern":"example/Other[.]class"}],"excludes":[{"pattern":"example/Required[.]class"}]}}
        """;
    final String ownExclude =
        """
        {"resources":{"includes":[{"pattern":"example/Required[.]class"}],"excludes":[{"pattern":"example/Required[.]class"}]}}
        """;

    final Path directDuplicate =
        NativeImageScanContextTestSupport.duplicateEntryJar(
            temporaryDirectory,
            "direct-duplicate-resource.jar",
            "META-INF/native-image/example/resource-config.json",
            includeRequired,
            "META-INF/native-image/example/resource-confix.json",
            excludeRequired);
    final Path directOwnExcludeJar =
        NativeImageScanContextTestSupport.jar(
            temporaryDirectory,
            "direct-own-exclude.jar",
            "META-INF/native-image/example/resource-config.json",
            ownExclude);

    final Path pointerDeclaring =
        NativeImageScanContextTestSupport.jar(
            temporaryDirectory,
            "pointer-declaring.jar",
            NativeImageScanContextTestSupport.PROPERTIES_ENTRY,
            "Args = -H:ResourceConfigurationResources=configs/resource-config.json\n");
    final Path pointerDuplicate =
        NativeImageScanContextTestSupport.duplicateEntryJar(
            temporaryDirectory,
            "pointer-duplicate-provider.jar",
            "configs/resource-config.json",
            includeRequired,
            "configs/resource-confix.json",
            excludeRequired);

    final ResolvedScan directDup = resolveScan(directDuplicate, "direct-dup", provider);
    final ResolvedScan directOwnExclude = resolveScan(directOwnExcludeJar, "direct-own", provider);
    final NativeImageScanContext pointerContext =
        NativeImageScanContext.create(
            List.of(
                NativeImageScanContextTestSupport.candidate("declaring", pointerDeclaring),
                NativeImageScanContextTestSupport.candidate("pointer-dup", pointerDuplicate),
                NativeImageScanContextTestSupport.candidate("provider", provider)),
            temporaryDirectory);
    final DependencyDynamicRoots.RootScan pointerRaw =
        DependencyDynamicRoots.scan(pointerDeclaring, pointerContext);
    final Set<String> pointerRoots = new LinkedHashSet<>(pointerRaw.roots());
    final Set<Path> pointerProviders = new LinkedHashSet<>(pointerRaw.resourceProviders());
    NativeImagePolicyRoots.applyResourcePatterns(
        List.of(pointerRaw.resourcePatterns()), pointerContext, pointerRoots, pointerProviders);

    assertAll(
        "Per-physical-descriptor resource exclusion scoping",
        () -> assertThat(directDup.roots()).contains("example.Required"),
        () -> assertThat(directDup.providers()).contains(provider),
        () -> assertThat(directOwnExclude.roots()).doesNotContain("example.Required"),
        () -> assertThat(directOwnExclude.providers()).doesNotContain(provider),
        () -> assertThat(pointerRoots).contains("example.Required"),
        () -> assertThat(pointerProviders).contains(provider));
  }

  private record ResolvedScan(Set<String> roots, Set<Path> providers) {}

  private ResolvedScan resolveScan(final Path declaring, final String name, final Path provider)
      throws IOException {
    final NativeImageScanContext context =
        NativeImageScanContext.create(
            List.of(
                NativeImageScanContextTestSupport.candidate(name, declaring),
                NativeImageScanContextTestSupport.candidate("provider", provider)),
            temporaryDirectory);
    final DependencyDynamicRoots.RootScan raw = DependencyDynamicRoots.scan(declaring, context);
    final Set<String> roots = new LinkedHashSet<>(raw.roots());
    final Set<Path> providers = new LinkedHashSet<>(raw.resourceProviders());
    NativeImagePolicyRoots.applyResourcePatterns(
        List.of(raw.resourcePatterns()), context, roots, providers);
    return new ResolvedScan(roots, providers);
  }

  /* package */
  @Test
  void usesSelectiveReadsForOrdinaryJarsAndSequentialStreamOnlyForDuplicateMetadata()
      throws IOException {
    final Path largeOrdinaryJar = temporaryDirectory.resolve("large-ordinary.jar");
    try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(largeOrdinaryJar))) {
      output.putNextEntry(new JarEntry("assets/large-zeros.bin"));
      output.write(new byte[1024 * 1024]);
      output.closeEntry();
    }
    final Path singleDescriptorJar =
        NativeImageScanContextTestSupport.jar(
            temporaryDirectory,
            "single-descriptor.jar",
            "META-INF/native-image/example/reflect-config.json",
            NativeImageScanContextTestSupport.reflection("example.Single"),
            "assets/other.txt",
            "ignored");
    final Path duplicateDescriptorJar =
        NativeImageScanContextTestSupport.duplicateEntryJar(
            temporaryDirectory,
            "duplicate-descriptor.jar",
            "META-INF/native-image/example/reflect-config.json",
            NativeImageScanContextTestSupport.reflection("example.First"),
            "META-INF/native-image/example/reflect-confix.json",
            NativeImageScanContextTestSupport.reflection("example.Second"));

    final AtomicInteger ordinarySequentialOpens = new AtomicInteger();
    final AtomicInteger singleSequentialOpens = new AtomicInteger();
    final AtomicInteger duplicateSequentialOpens = new AtomicInteger();

    final DependencyDynamicRoots.RootScan ordinaryScan =
        DependencyDynamicRoots.scan(
            largeOrdinaryJar,
            NativeImageScanContext.singleArchive(largeOrdinaryJar),
            path -> {
              ordinarySequentialOpens.incrementAndGet();
              return Files.newInputStream(path);
            });
    final DependencyDynamicRoots.RootScan singleScan =
        DependencyDynamicRoots.scan(
            singleDescriptorJar,
            NativeImageScanContext.singleArchive(singleDescriptorJar),
            path -> {
              singleSequentialOpens.incrementAndGet();
              return Files.newInputStream(path);
            });
    final DependencyDynamicRoots.RootScan duplicateScan =
        DependencyDynamicRoots.scan(
            duplicateDescriptorJar,
            NativeImageScanContext.singleArchive(duplicateDescriptorJar),
            path -> {
              duplicateSequentialOpens.incrementAndGet();
              return Files.newInputStream(path);
            });

    assertAll(
        "Selective archive scan vs duplicate sequential fallback",
        () -> assertThat(ordinaryScan.roots()).isEmpty(),
        () -> assertThat(ordinarySequentialOpens.get()).isZero(),
        () -> assertThat(singleScan.roots()).containsExactly("example.Single"),
        () -> assertThat(singleSequentialOpens.get()).isZero(),
        () ->
            assertThat(duplicateScan.roots())
                .containsExactlyInAnyOrder("example.First", "example.Second"),
        () -> assertThat(duplicateSequentialOpens.get()).isEqualTo(1));
  }

  /* package */
  @Test
  void preservesResourceRootWhenDirectAndPointerScansCoexistWithPrecedingMetadata()
      throws IOException {
    final Path provider = validClassJar("combined-provider.jar", "example/Required");
    final String includeRequired =
        """
        {"resources":{"includes":[{"pattern":"example/Required[.]class"}]}}
        """;
    final String excludeRequired =
        """
        {"resources":{"includes":[{"pattern":"example/Other[.]class"}],"excludes":[{"pattern":"example/Required[.]class"}]}}
        """;
    final String ownExclude =
        """
        {"resources":{"includes":[{"pattern":"example/Required[.]class"}],"excludes":[{"pattern":"example/Required[.]class"}]}}
        """;
    final String resourceEntry = "META-INF/native-image/example/resource-config.json";
    final String propsEntry = "META-INF/native-image/example/native-image.properties";
    final String pointerProps = "Args = -H:ResourceConfigurationResources=" + resourceEntry + "\n";

    final Path directOnly =
        writeDuplicateResourceJar(
            "combined-direct-only.jar",
            null,
            null,
            excludeRequired,
            includeRequired,
            excludeRequired);
    final Path directAndPointer =
        writeDuplicateResourceJar(
            "combined-direct-and-pointer.jar",
            propsEntry,
            pointerProps,
            excludeRequired,
            includeRequired,
            excludeRequired);

    final Path ownExcludeJar =
        NativeImageScanContextTestSupport.jar(
            temporaryDirectory, "combined-own-exclude.jar", resourceEntry, ownExclude);

    final ResolvedScan directResult = resolveScan(directOnly, "direct-only", provider);
    final ResolvedScan combinedResult =
        resolveScan(directAndPointer, "direct-and-pointer", provider);
    final ResolvedScan ownExcludeResult = resolveScan(ownExcludeJar, "own-exclude", provider);

    assertAll(
        "Combined direct and pointer duplicate resource exclusion scoping",
        () -> assertThat(directResult.roots()).contains("example.Required"),
        () -> assertThat(directResult.providers()).contains(provider),
        () -> assertThat(combinedResult.roots()).contains("example.Required"),
        () -> assertThat(combinedResult.providers()).contains(provider),
        () -> assertThat(combinedResult.roots()).isEqualTo(directResult.roots()),
        () ->
            assertThat(combinedResult.providers())
                .containsExactlyInAnyOrder(directAndPointer, provider),
        () -> assertThat(ownExcludeResult.roots()).doesNotContain("example.Required"),
        () -> assertThat(ownExcludeResult.providers()).doesNotContain(provider));
  }

  private Path writeDuplicateResourceJar(
      final String jarName,
      final String propsEntry,
      final String pointerProps,
      final String firstBody,
      final String secondBody,
      final String thirdBody)
      throws IOException {
    final Path jarPath = temporaryDirectory.resolve(jarName);
    try (JarOutputStream out = new JarOutputStream(Files.newOutputStream(jarPath))) {
      if (propsEntry != null) {
        writeUtf8Entry(out, propsEntry, pointerProps);
      }
      writeUtf8Entry(out, "META-INF/native-image/example/resource-confi1.json", firstBody);
      writeUtf8Entry(out, "META-INF/native-image/example/resource-confi2.json", secondBody);
      writeUtf8Entry(out, "META-INF/native-image/example/resource-confi3.json", thirdBody);
    }
    String raw =
        new String(Files.readAllBytes(jarPath), java.nio.charset.StandardCharsets.ISO_8859_1);
    raw =
        raw.replace("resource-confi1.json", "resource-config.json")
            .replace("resource-confi2.json", "resource-config.json")
            .replace("resource-confi3.json", "resource-config.json");
    Files.write(jarPath, raw.getBytes(java.nio.charset.StandardCharsets.ISO_8859_1));
    return jarPath;
  }

  private static void writeUtf8Entry(
      final JarOutputStream out, final String name, final String content) throws IOException {
    out.putNextEntry(new JarEntry(name));
    out.write(content.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    out.closeEntry();
  }

  private Path validClassJar(final String jarName, final String internalName) throws IOException {
    final ClassWriter writer = new ClassWriter(0);
    writer.visit(Opcodes.V21, Opcodes.ACC_PUBLIC, internalName, null, "java/lang/Object", null);
    writer.visitEnd();
    final Path jarPath = temporaryDirectory.resolve(jarName);
    try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(jarPath))) {
      output.putNextEntry(new JarEntry(internalName + ".class"));
      output.write(writer.toByteArray());
      output.closeEntry();
    }
    return jarPath;
  }
}
