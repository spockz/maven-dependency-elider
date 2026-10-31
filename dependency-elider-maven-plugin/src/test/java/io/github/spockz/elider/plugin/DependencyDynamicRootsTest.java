// WHY: Verifies scanning and partitioning of ServiceLoader SPI and other dynamic roots.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Handle;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;

/** Tests dependency dynamic roots scanning and effective roots partitioning. */
@SuppressWarnings({
  "PMD.CommentDefaultAccessModifier",
  "PMD.UnitTestContainsTooManyAsserts",
  "PMD.AtLeastOneConstructor",
  "PMD.TooManyMethods",
  "PMD.AvoidDuplicateLiterals"
})
final class DependencyDynamicRootsTest {
  /** Test service interface name. */
  private static final String MY_SERVICE = "org.example.spi.MyService";

  /** Dummy class byte payload. */
  private static final byte[] DUMMY_BYTE = {0};

  /** Temporary test directory. */
  @TempDir Path tempDir;

  @Test
  void readsArbitraryNamedDescriptorsAndFilesystemPredefinedSiblings() throws IOException {
    final Set<String> roots = new java.util.LinkedHashSet<>();
    final Path reflectionFile = tempDir.resolve("reflection.payload");
    Files.writeString(
        reflectionFile, "[{\"name\":\"org.example.ExplicitKind\"}]", StandardCharsets.UTF_8);
    NativeImageClassConfig.readNativeImageClassConfig(
        NativeImageInput.file(reflectionFile, NativeImageDescriptorKind.REFLECTION), roots);

    final Path archivePath = tempDir.resolve("explicit-kind-archive.jar");
    try (JarOutputStream out = new JarOutputStream(Files.newOutputStream(archivePath))) {
      put(out, "metadata.payload", "[{\"name\":\"org.example.ArchiveKind\"}]");
    }
    try (JarFile archive = new JarFile(archivePath.toFile())) {
      NativeImageClassConfig.readNativeImageClassConfig(
          NativeImageInput.archiveEntry(
              archive, "metadata.payload", NativeImageDescriptorKind.REFLECTION),
          roots);
    }

    final Path resourceFile = tempDir.resolve("resource.payload");
    Files.writeString(
        resourceFile,
        "{\"bundles\":[{\"name\":\"org.example.ExplicitBundle\"}]}",
        StandardCharsets.UTF_8);
    NativeImageResourceConfig.readNativeImageResourceConfig(
        NativeImageInput.file(resourceFile, NativeImageDescriptorKind.RESOURCES), roots);

    final String hash = "0123456789abcdef0123456789abcdef";
    final Path predefinedFile = tempDir.resolve("predefined.payload");
    Files.writeString(
        predefinedFile,
        "[{\"type\":\"agent-extracted\",\"classes\":[{\"hash\":\"" + hash + "\"}]}]",
        StandardCharsets.UTF_8);
    final Path classData = tempDir.resolve("agent-extracted-predefined-classes");
    Files.createDirectories(classData);
    final ClassWriter writer = new ClassWriter(0);
    writer.visit(
        Opcodes.V21,
        Opcodes.ACC_PUBLIC,
        "org/example/FilesystemGenerated",
        null,
        "org/example/FilesystemDependency",
        null);
    writer.visitEnd();
    Files.write(classData.resolve(hash + ".classdata"), writer.toByteArray());
    NativeImageClassConfig.readNativeImageClassConfig(
        NativeImageInput.file(predefinedFile, NativeImageDescriptorKind.PREDEFINED_CLASSES), roots);

    assertThat(roots)
        .contains(
            "org.example.ExplicitKind",
            "org.example.ArchiveKind",
            "org.example.ExplicitBundle",
            "org.example.FilesystemGenerated",
            "org.example.FilesystemDependency");
  }

  @Test
  void rejectsPredefinedClassdataEscapingThroughSymlink() throws IOException {
    final String hash = "0123456789abcdef0123456789abcdef";
    final Path descriptorDirectory = tempDir.resolve("descriptor-root");
    final Path externalDirectory = tempDir.resolve("external-classdata");
    Files.createDirectories(descriptorDirectory);
    Files.createDirectories(externalDirectory);
    final Path config = descriptorDirectory.resolve("arbitrary.data");
    Files.writeString(
        config,
        "[{\"type\":\"agent-extracted\",\"classes\":[{\"hash\":\"" + hash + "\"}]}]",
        StandardCharsets.UTF_8);
    final ClassWriter writer = new ClassWriter(0);
    writer.visit(
        Opcodes.V21, Opcodes.ACC_PUBLIC, "org/example/Escaped", null, "java/lang/Object", null);
    writer.visitEnd();
    Files.write(externalDirectory.resolve(hash + ".classdata"), writer.toByteArray());
    Files.createSymbolicLink(
        descriptorDirectory.resolve("agent-extracted-predefined-classes"), externalDirectory);

    final Set<String> roots = new java.util.LinkedHashSet<>();
    assertThatThrownBy(
            () ->
                NativeImageClassConfig.readNativeImageClassConfig(
                    NativeImageInput.file(config, NativeImageDescriptorKind.PREDEFINED_CLASSES),
                    roots))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("Unresolved predefined class hash");
  }

  @Test
  void distinguishesProvenAndUnprovenServiceRoots() throws IOException {
    final Path jar = tempDir.resolve("spi-service.jar");
    try (JarOutputStream out = new JarOutputStream(Files.newOutputStream(jar))) {
      out.putNextEntry(new JarEntry("org/example/spi/MyService.class"));
      out.write(DUMMY_BYTE);
      out.closeEntry();
      out.putNextEntry(new JarEntry("org/example/spi/MyServiceImpl.class"));
      out.write(DUMMY_BYTE);
      out.closeEntry();
      out.putNextEntry(new JarEntry("org/example/spi/OtherService.class"));
      out.write(DUMMY_BYTE);
      out.closeEntry();
      out.putNextEntry(new JarEntry("org/example/spi/OtherServiceImpl.class"));
      out.write(DUMMY_BYTE);
      out.closeEntry();
      out.putNextEntry(new JarEntry("META-INF/services/" + MY_SERVICE));
      out.write("org.example.spi.MyServiceImpl\n".getBytes(StandardCharsets.UTF_8));
      out.closeEntry();
      out.putNextEntry(new JarEntry("META-INF/services/org.example.spi.OtherService"));
      out.write("org.example.spi.OtherServiceImpl\n".getBytes(StandardCharsets.UTF_8));
      out.closeEntry();
    }

    final DependencyDynamicRoots.RootScan scan = DependencyDynamicRoots.scan(jar);
    assertThat(scan.declaresClassRoots()).isTrue();
    assertThat(scan.serviceDescriptors()).hasSize(2);

    // Case 1: MyService is proven, OtherService is not. Fallback enabled (default).
    final DependencyDynamicRoots.EffectiveRoots conservative =
        scan.effectiveRoots(Set.of(MY_SERVICE), true);

    assertThat(conservative.roots())
        .contains(
            MY_SERVICE,
            "org.example.spi.MyServiceImpl",
            "org.example.spi.OtherService",
            "org.example.spi.OtherServiceImpl");
    assertThat(conservative.unprovenConservativeRoots())
        .containsExactlyInAnyOrder(
            "org.example.spi.OtherService", "org.example.spi.OtherServiceImpl");

    // Case 2: MyService is proven, OtherService is not. Fallback disabled.
    final DependencyDynamicRoots.EffectiveRoots nonConservative =
        scan.effectiveRoots(Set.of(MY_SERVICE), false);

    assertThat(nonConservative.roots())
        .containsExactlyInAnyOrder(MY_SERVICE, "org.example.spi.MyServiceImpl");
    assertThat(nonConservative.unprovenConservativeRoots()).isEmpty();
    assertThat(nonConservative.unprovenConservativeServices()).isEmpty();
  }

  @Test
  void parsesOkHttpArgsAndRetainsFeatureRoot() throws IOException {
    final Path jar =
        nativeImageJar(
            "Args = -H:+AddAllCharsets --enable-http --enable-https "
                + "--features=okhttp3.internal.graal.OkHttpFeature "
                + "--report-unsupported-elements-at-runtime\n");

    final DependencyDynamicRoots.RootScan scan = DependencyDynamicRoots.scan(jar);

    assertThat(scan.roots()).contains("okhttp3.internal.graal.OkHttpFeature");
  }

  @Test
  void parsesAuditedDirectClassRootOptions() throws IOException {
    final Path jar =
        nativeImageJar(
            "Args = --features=org.example.FeatureOne,org.example.FeatureTwo "
                + "-H:Features=org.example.HFeature "
                + "-H:Class=org.example.Entry --main-class=org.example.Main "
                + "--trace-class-initialization=org.example.InitTrace "
                + "-H:TraceClassInitialization=org.example.HInitTrace "
                + "--trace-object-instantiation=org.example.ObjectTrace "
                + "-H:TraceObjectInstantiation=org.example.HObjectTrace "
                + "-H:AdditionalSecurityProviders=org.example.Provider "
                + "-H:AdditionalSecurityServiceTypes=org.example.SecurityType "
                + "-H:IncludeResourceBundles=org.example.Messages,org.example.MoreMessages,"
                + "Legacy-Bundle\n");

    final DependencyDynamicRoots.RootScan scan = DependencyDynamicRoots.scan(jar);

    assertThat(scan.roots())
        .containsExactlyInAnyOrder(
            "org.example.FeatureOne",
            "org.example.FeatureTwo",
            "org.example.HFeature",
            "org.example.Entry",
            "org.example.Main",
            "org.example.InitTrace",
            "org.example.HInitTrace",
            "org.example.ObjectTrace",
            "org.example.HObjectTrace",
            "org.example.Provider",
            "org.example.SecurityType");
  }

  @Test
  void rejectsMalformedClassOnlyListsAndInitializationStrategies() throws IOException {
    for (final String argument :
        new String[] {
          "--features=",
          "--features=org.example.One,,org.example.Two",
          "-H:Features=org.example.Bad-Name",
          "-H:Class=org.example.One,org.example.Two",
          "--main-class=org.example.Bad-Name",
          "--trace-object-instantiation=org.example.One,",
          "-H:AdditionalSecurityProviders=org.example.Bad-Name",
          "-H:AdditionalSecurityServiceTypes=",
          "-H:IncludeResourceBundles=org.example.One,,org.example.Two",
          "-H:ClassInitialization",
          "-H:ClassInitialization=",
          "-H:ClassInitialization=org.example.Type",
          "-H:ClassInitialization=org.example.Type:runtime",
          "-H:ClassInitialization=org.example.Type:run_time,",
          "--initialize-at-build-time=,org.example.Type"
        }) {
      final Path jar = nativeImageJar("Args = " + argument + "\n");
      assertThatThrownBy(() -> DependencyDynamicRoots.scan(jar))
          .as(argument)
          .isInstanceOf(IOException.class);
    }
  }

  @Test
  void rejectsMalformedUnifiedMethodParameterTypes() throws IOException {
    for (final String parameter : new String[] {"org.example.Bad-Name", "void[]"}) {
      final Path jar =
          nativeImageJar(
              "Args = --initialize-at-build-time\n",
              "META-INF/native-image/test/reachability-metadata.json",
              "{\"reflection\":[{\"type\":\"org.example.Owner\","
                  + "\"methods\":[{\"name\":\"call\",\"parameterTypes\":[\""
                  + parameter
                  + "\"]}]}]}");
      assertThatThrownBy(() -> DependencyDynamicRoots.scan(jar))
          .isInstanceOf(IOException.class)
          .hasMessageContaining("Malformed reachability method parameter type");
    }
  }

  @Test
  void rejectsVoidArraysAsClassNames() {
    assertThat(NativeImageTypeDescriptor.extractComponentClass("void[]")).isNull();
    assertThat(NativeImageTypeDescriptor.extractComponentClass("void[][]")).isNull();
  }

  @Test
  void loadsJavaPropertiesContinuationBeforeTokenizingArgs() throws IOException {
    final Path jar =
        nativeImageJar("Args = --features=org.example.Feature \\\n" + "  --enable-http\n");

    final DependencyDynamicRoots.RootScan scan = DependencyDynamicRoots.scan(jar);

    assertThat(scan.roots()).contains("org.example.Feature");
  }

  @Test
  void stripsQuotesAndAcceptsUnknownArgumentsWithoutRoots() throws IOException {
    final Path jar =
        nativeImageJar(
            "Args = \"-H:ReflectionConfigurationResources=${.}/reflect-config.json\" "
                + "'--enable-http' -H:CustomFlag='some value'\n",
            "META-INF/native-image/test/reflect-config.json",
            "[{\"name\":\"org.example.Reflective\"}]");

    final DependencyDynamicRoots.RootScan scan = DependencyDynamicRoots.scan(jar);

    assertThat(scan.roots()).contains("org.example.Reflective");
  }

  @Test
  void acceptsUnknownAndAuditedNoRootArgumentsWithoutDeclaringRoots() throws IOException {
    final Path jar = nativeImageJar("Args = -H:UnknownFlag=value -march=native --pgo --gc=G1\n");

    final DependencyDynamicRoots.RootScan scan = DependencyDynamicRoots.scan(jar);

    assertThat(scan.roots()).isEmpty();
    assertThat(scan.declaresClassRoots()).isFalse();
  }

  @Test
  void rejectsUnmatchedQuotes() throws IOException {
    final Path jar = nativeImageJar("Args = --features='org.example.Feature\n");
    assertThatThrownBy(() -> DependencyDynamicRoots.scan(jar))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("Unmatched quote");
  }

  @Test
  void doesNotAllowBareModeledRootNamesToBypassValidation() throws IOException {
    final Path jar = nativeImageJar("Args = --features\n");
    assertThatThrownBy(() -> DependencyDynamicRoots.scan(jar))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("root option has no value");
  }

  @Test
  void extractsArrayAndDescriptorRootsInReflectConfig() throws IOException {
    final String reflectConfig =
        "[\n"
            + "  {\n"
            + "    \"name\": \"kotlin.internal.jdk8.JDK8PlatformImplementations\",\n"
            + "    \"allDeclaredConstructors\": true\n"
            + "  },\n"
            + "  {\n"
            + "    \"name\": \"kotlin.KotlinVersion\",\n"
            + "    \"allPublicMethods\": true,\n"
            + "    \"allDeclaredFields\": true,\n"
            + "    \"allDeclaredMethods\": true,\n"
            + "    \"allDeclaredConstructors\": true\n"
            + "  },\n"
            + "  {\n"
            + "    \"name\": \"kotlin.KotlinVersion[]\"\n"
            + "  },\n"
            + "  {\n"
            + "    \"name\": \"kotlin.KotlinVersion$Companion\"\n"
            + "  },\n"
            + "  {\n"
            + "    \"name\": \"kotlin.KotlinVersion$Companion[]\"\n"
            + "  },\n"
            + "  {\n"
            + "    \"name\": \"[Lorg.example.Widget;\"\n"
            + "  },\n"
            + "  {\n"
            + "    \"name\": \"[[Lorg/example/MultiLevel;\"\n"
            + "  },\n"
            + "  {\n"
            + "    \"name\": \"int[]\"\n"
            + "  },\n"
            + "  {\n"
            + "    \"name\": \"[B\"\n"
            + "  },\n"
            + "  {\n"
            + "    \"name\": \"int\"\n"
            + "  }\n"
            + "]";

    final Path jar =
        nativeImageJar(
            "Args = \"-H:ReflectionConfigurationResources=${.}/reflect-config.json\"\n",
            "META-INF/native-image/test/reflect-config.json",
            reflectConfig);

    final DependencyDynamicRoots.RootScan scan = DependencyDynamicRoots.scan(jar);

    assertThat(scan.roots())
        .containsExactlyInAnyOrder(
            "kotlin.internal.jdk8.JDK8PlatformImplementations",
            "kotlin.KotlinVersion",
            "kotlin.KotlinVersion$Companion",
            "org.example.Widget",
            "org.example.MultiLevel");
  }

  @Test
  void rejectsMalformedArrayOrClassNamesInReflectConfig() throws IOException {
    final Path jar =
        nativeImageJar(
            "Args = \"-H:ReflectionConfigurationResources=${.}/reflect-config.json\"\n",
            "META-INF/native-image/test/reflect-config.json",
            "[{\"name\":\"invalid..ClassName[]\"}]");

    assertThatThrownBy(() -> DependencyDynamicRoots.scan(jar))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("Malformed standalone type descriptor");
  }

  @Test
  void extractsRootsFromUnifiedReachabilityMetadata() throws IOException {
    final String reachabilityMetadata =
        """
        {
          "comment": "schema 1.2",
          "reflection": [
            {"type":"org.example.Primary","condition":{"typeReached":"org.example.Gate"},
             "methods":[{"name":"make","parameterTypes":["org.example.Argument[]"]}]},
            {"type":{"proxy":["org.example.ProxyApi"]}},
            {"type":{"lambda":{"declaringClass":"org.example.LambdaOwner",
              "interfaces":["org.example.LambdaApi"]}}}
          ],
          "resources": [{"bundle":"org.example.Messages",
            "condition":{"typeReached":"org.example.BundleGate"}}],
          "foreign": {"directUpcalls":[{"class":"org.example.Callback","method":"invoke"}]}
        }
        """;

    final Path jar = tempDir.resolve("reachability-metadata-" + System.nanoTime() + ".jar");
    try (JarOutputStream out = new JarOutputStream(Files.newOutputStream(jar))) {
      out.putNextEntry(new JarEntry("META-INF/native-image/test/group/reachability-metadata.json"));
      out.write(reachabilityMetadata.getBytes(StandardCharsets.UTF_8));
      out.closeEntry();
    }

    final DependencyDynamicRoots.RootScan scan = DependencyDynamicRoots.scan(jar);

    assertThat(scan.roots())
        .containsExactlyInAnyOrder(
            "org.example.Primary",
            "org.example.Gate",
            "org.example.Argument",
            "org.example.ProxyApi",
            "org.example.LambdaOwner",
            "org.example.LambdaApi",
            "org.example.BundleGate",
            "org.example.Callback");
  }

  @Test
  void readsStandaloneSerializationAndReflectionSecondaryTypes() throws IOException {
    final Path jar = tempDir.resolve("native-image-descriptors-" + System.nanoTime() + ".jar");
    try (JarOutputStream out = new JarOutputStream(Files.newOutputStream(jar))) {
      put(
          out,
          "META-INF/native-image/test/serialization-config.json",
          """
          [{"name":"org.example.Payload",
            "customTargetConstructorClass":"org.example.Target"}]
          """);
      put(
          out,
          "META-INF/native-image/test/reflect-config.json",
          """
          [{"name":"org.example.Reflective",
            "methods":[{"name":"open","parameterTypes":["org.example.MethodParameter"]}]}]
          """);
    }
    final DependencyDynamicRoots.RootScan scan = DependencyDynamicRoots.scan(jar);
    assertThat(scan.roots())
        .contains(
            "org.example.Payload",
            "org.example.Target",
            "org.example.Reflective",
            "org.example.MethodParameter");

    final Path invalidLegacySections =
        nativeImageJar(
            "Args = --initialize-at-build-time\n",
            "META-INF/native-image/test/serialization-config.json",
            "[{\"name\":\"org.example.Payload\","
                + "\"lambdaCapturingTypes\":[\"org.example.Captured\"]}]");
    assertThatThrownBy(() -> DependencyDynamicRoots.scan(invalidLegacySections))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("Unsupported native-image legacy serialization entry field");

    final Path invalidLegacyProxies =
        nativeImageJar(
            "Args = --initialize-at-build-time\n",
            "META-INF/native-image/test/serialization-config.json",
            "[{\"name\":\"org.example.Payload\","
                + "\"proxies\":[{\"interfaces\":[\"org.example.Proxy\"]}]}]");
    assertThatThrownBy(() -> DependencyDynamicRoots.scan(invalidLegacyProxies))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("Unsupported native-image legacy serialization entry field");

    final Path schemaJar = tempDir.resolve("serialization-schema-" + System.nanoTime() + ".jar");
    try (JarOutputStream out = new JarOutputStream(Files.newOutputStream(schemaJar))) {
      put(
          out,
          "META-INF/native-image/test/serialization-config.json",
          """
          {"types":[{"name":"org.example.SchemaPayload",
            "customTargetConstructorClass":"org.example.SchemaTarget",
            "condition":{"typeReachable":"org.example.SerializationGate"}}],
           "lambdaCapturingTypes":[{"name":"org.example.Capturer",
            "condition":{"typeReachable":"org.example.LambdaGate"}}],
           "proxies":[{"interfaces":["org.example.SerializableProxy"],
            "condition":{"typeReachable":"org.example.ProxyGate"}}]}
          """);
    }
    assertThat(DependencyDynamicRoots.scan(schemaJar).roots())
        .contains(
            "org.example.SchemaPayload",
            "org.example.SchemaTarget",
            "org.example.SerializationGate",
            "org.example.Capturer",
            "org.example.LambdaGate",
            "org.example.SerializableProxy",
            "org.example.ProxyGate");

    final Path emptySchema = tempDir.resolve("serialization-empty-" + System.nanoTime() + ".jar");
    try (JarOutputStream out = new JarOutputStream(Files.newOutputStream(emptySchema))) {
      put(
          out,
          "META-INF/native-image/test/serialization-config.json",
          "{\"types\":[],\"lambdaCapturingTypes\":[],\"proxies\":[]}");
    }
    assertThat(DependencyDynamicRoots.scan(emptySchema).roots()).isEmpty();

    final Path omittedProxies =
        tempDir.resolve("serialization-no-proxies-" + System.nanoTime() + ".jar");
    try (JarOutputStream out = new JarOutputStream(Files.newOutputStream(omittedProxies))) {
      put(
          out,
          "META-INF/native-image/test/serialization-config.json",
          "{\"types\":[],\"lambdaCapturingTypes\":[]}");
    }
    assertThat(DependencyDynamicRoots.scan(omittedProxies).roots()).isEmpty();

    final Path missingSections =
        nativeImageJar(
            "Args = --initialize-at-build-time\n",
            "META-INF/native-image/test/serialization-config.json",
            "{}");
    assertThatThrownBy(() -> DependencyDynamicRoots.scan(missingSections))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("Malformed serialization types");

    final Path unsupported = tempDir.resolve("unsupported-unified-" + System.nanoTime() + ".jar");
    try (JarOutputStream out = new JarOutputStream(Files.newOutputStream(unsupported))) {
      put(out, "META-INF/native-image/test/reachability-metadata.json", "{\"serialization\": []}");
    }
    assertThatThrownBy(() -> DependencyDynamicRoots.scan(unsupported))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("Unsupported native-image reachability metadata field serialization");
  }

  @Test
  void rejectsDuplicateKeysAndTrailingMetadataJson() throws IOException {
    for (final String json :
        new String[] {"[{\"name\":\"a.A\",\"name\":\"b.B\"}]", "[{\"name\":\"a.A\"}] {}"}) {
      final Path jar = nativeImageConfigJar(json);
      assertThatThrownBy(() -> DependencyDynamicRoots.scan(jar)).isInstanceOf(IOException.class);
    }
  }

  @Test
  void keepsStandaloneConditionsClassOnlyAndRejectsAmbiguousKeys() throws IOException {
    final Path objectCondition =
        nativeImageJar(
            "Args = --initialize-at-build-time\n",
            "META-INF/native-image/test/reflect-config.json",
            "[{\"name\":\"org.example.Type\",\"condition\":{\"typeReached\":"
                + "{\"proxy\":[\"org.example.Proxy\"]}}}]");
    assertThatThrownBy(() -> DependencyDynamicRoots.scan(objectCondition))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("condition class name");

    final Path ambiguousCondition =
        nativeImageJar(
            "Args = --initialize-at-build-time\n",
            "META-INF/native-image/test/reflect-config.json",
            "[{\"name\":\"org.example.Type\",\"condition\":{"
                + "\"typeReached\":\"org.example.One\","
                + "\"typeReachable\":\"org.example.Two\"}}]");
    assertThatThrownBy(() -> DependencyDynamicRoots.scan(ambiguousCondition))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("native-image condition");
  }

  @Test
  void acceptsPinnedReflectionBooleansAndRejectsUnsupportedAliases() throws IOException {
    final Path valid =
        nativeImageJar(
            "Args = --initialize-at-build-time\n",
            "META-INF/native-image/test/reflect-config.json",
            "[{\"name\":\"org.example.ReflectFlags\",\"allDeclaredConstructors\":true,"
                + "\"allPublicConstructors\":true,\"allDeclaredMethods\":true,"
                + "\"allPublicMethods\":true,\"allDeclaredFields\":true,"
                + "\"allPublicFields\":true,\"allDeclaredClasses\":true,"
                + "\"allPublicClasses\":true,\"allRecordComponents\":true,"
                + "\"allPermittedSubclasses\":true,\"allNestMembers\":true,"
                + "\"allSigners\":true,\"queryAllDeclaredConstructors\":true,"
                + "\"queryAllPublicConstructors\":true,\"queryAllDeclaredMethods\":true,"
                + "\"queryAllPublicMethods\":true,\"unsafeAllocated\":true}]");
    assertThat(DependencyDynamicRoots.scan(valid).roots()).contains("org.example.ReflectFlags");

    final Path unsupported =
        nativeImageJar(
            "Args = --initialize-at-build-time\n",
            "META-INF/native-image/test/reflect-config.json",
            "[{\"type\":\"org.example.TypeAlias\"}]");
    assertThatThrownBy(() -> DependencyDynamicRoots.scan(unsupported))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("Unsupported native-image reflect entry field type");
  }

  @Test
  void validatesDenyLambdaFieldsAndResourceGlobSchemas() throws IOException {
    final Path invalidDenyLambda =
        nativeImageJar(
            "Args = --initialize-at-build-time\n",
            "META-INF/native-image/test/serialization-deny-config.json",
            "{\"types\":[],\"lambdaCapturingTypes\":["
                + "{\"name\":\"org.example.DenyLambda\","
                + "\"customTargetConstructorClass\":\"org.example.Invalid\"}],"
                + "\"proxies\":[]}");
    assertThatThrownBy(() -> DependencyDynamicRoots.scan(invalidDenyLambda))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("Unsupported native-image serialization-deny lambda type field");

    final Path emptyReason =
        nativeImageJar(
            "Args = --initialize-at-build-time\n",
            "META-INF/native-image/test/reachability-metadata.json",
            "{\"reflection\":[{\"type\":\"org.example.EmptyReason\","
                + "\"reason\":\"\"}],\"resources\":[{\"glob\":"
                + "\"sample\\\\.txt\",\"reason\":[\"\"]}]}");
    assertThat(DependencyDynamicRoots.scan(emptyReason).roots())
        .contains("org.example.EmptyReason");

    final Path resourceConfig =
        nativeImageJar(
            "Args = --initialize-at-build-time\n",
            "META-INF/native-image/test/resource-config.json",
            "{\"bundles\":[{\"name\":\"org.example.Messages\","
                + "\"locales\":[\"fr\"]}],\"globs\":[{\"glob\":"
                + "\"sample/**\",\"condition\":{"
                + "\"typeReachable\":\"org.example.GlobGate\"},"
                + "\"module\":\"m.test\"}]}");
    assertThat(DependencyDynamicRoots.scan(resourceConfig).roots())
        .containsExactly("org.example.GlobGate");

    final Path bundleOnly =
        nativeImageJar(
            "Args = --initialize-at-build-time\n",
            "META-INF/native-image/test/resource-config.json",
            "{\"bundles\":[{\"name\":\"org.example.BundleOnly\",\"locales\":[\"de\"]}]}");
    assertThat(DependencyDynamicRoots.scan(bundleOnly).roots()).isEmpty();

    final Path unknownGlobField =
        nativeImageJar(
            "Args = --initialize-at-build-time\n",
            "META-INF/native-image/test/resource-config.json",
            "{\"globs\":[{\"glob\":\"sample/**\",\"unknown\":true}]}");
    assertThatThrownBy(() -> DependencyDynamicRoots.scan(unknownGlobField))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("Unsupported native-image resource pattern field unknown");
  }

  @Test
  void rejectsLegacySerializationDenyNestedSections() throws IOException {
    for (final String nestedField :
        new String[] {
          "\"proxies\":[{\"interfaces\":[\"org.example.DeniedProxy\"]}]",
          "\"lambdaCapturingTypes\":[{\"name\":\"org.example.DeniedLambda\"}]"
        }) {
      final Path jar =
          nativeImageJar(
              "Args = --initialize-at-build-time\n",
              "META-INF/native-image/test/serialization-deny-config.json",
              "[{\"name\":\"org.example.Denied\"," + nestedField + "}]");
      assertThatThrownBy(() -> DependencyDynamicRoots.scan(jar))
          .isInstanceOf(IOException.class)
          .hasMessageContaining("Unsupported native-image serialization-deny entry field");
    }
  }

  private Path nativeImageConfigJar(final String json) throws IOException {
    final Path jar = tempDir.resolve("malformed-config-" + System.nanoTime() + ".jar");
    try (JarOutputStream out = new JarOutputStream(Files.newOutputStream(jar))) {
      put(out, "META-INF/native-image/test/reflect-config.json", json);
    }
    return jar;
  }

  @Test
  void resolvesHashOnlyPredefinedClassesFromAssociatedBytecode() throws IOException {
    final ClassWriter writer = new ClassWriter(0);
    writer.visit(
        Opcodes.V21, Opcodes.ACC_PUBLIC, "org/example/Generated", null, "java/lang/Object", null);
    writer.visitNestHost("org/example/GeneratedOuter");
    writer.visitNestMember("org/example/GeneratedInner");
    writer.visitPermittedSubclass("org/example/GeneratedPermitted");
    writer
        .visitField(
            Opcodes.ACC_PRIVATE,
            "dependency",
            "Ljava/util/List;",
            "Ljava/util/List<Lorg/example/GenericType;>;",
            null)
        .visitEnd();
    writer
        .visitField(
            Opcodes.ACC_PRIVATE,
            "nestedDependency",
            "Ljava/util/List;",
            "Ljava/util/List<Lorg/example/GenericOuter<Lorg/example/GenericArgument;>.Inner;>;",
            null)
        .visitEnd();
    final MethodVisitor method = writer.visitMethod(Opcodes.ACC_PUBLIC, "load", "()V", null, null);
    method.visitCode();
    method.visitLdcInsn(Type.getType("Lorg/example/LdcType;"));
    method.visitInsn(Opcodes.POP);
    method.visitInvokeDynamicInsn(
        "run",
        "()Ljava/lang/Runnable;",
        new Handle(
            Opcodes.H_INVOKESTATIC,
            "org/example/BootstrapOwner",
            "bootstrap",
            "()Ljava/lang/Object;",
            false),
        Type.getObjectType("org/example/BootstrapArgument"));
    method.visitInsn(Opcodes.POP);
    method.visitInsn(Opcodes.RETURN);
    method.visitMaxs(1, 1);
    method.visitEnd();
    writer.visitEnd();
    final Path jar = tempDir.resolve("predefined-" + System.nanoTime() + ".jar");
    try (JarOutputStream out = new JarOutputStream(Files.newOutputStream(jar))) {
      put(
          out,
          "META-INF/native-image/test/predefined-classes-config.json",
          """
          [{"type":"agent-extracted",
            "classes":[{"hash":"0123456789abcdef0123456789abcdef","nameInfo":null}]}]
          """);
      out.putNextEntry(
          new JarEntry(
              "META-INF/native-image/test/agent-extracted-predefined-classes/"
                  + "0123456789abcdef0123456789abcdef.classdata"));
      out.write(writer.toByteArray());
      out.closeEntry();
    }
    final DependencyDynamicRoots.RootScan scan = DependencyDynamicRoots.scan(jar);
    assertThat(scan.roots())
        .contains(
            "org.example.Generated",
            "java.util.List",
            "org.example.GenericType",
            "org.example.GenericOuter",
            "org.example.GenericOuter$Inner",
            "org.example.GenericArgument",
            "org.example.LdcType",
            "org.example.GeneratedOuter",
            "org.example.GeneratedInner",
            "org.example.GeneratedPermitted",
            "org.example.BootstrapOwner",
            "org.example.BootstrapArgument");
    assertThat(scan.roots()).doesNotContain("org.example.GenericArgument$Inner");

    final Path missing = tempDir.resolve("predefined-missing-" + System.nanoTime() + ".jar");
    try (JarOutputStream out = new JarOutputStream(Files.newOutputStream(missing))) {
      put(
          out,
          "META-INF/native-image/test/predefined-classes-config.json",
          """
          [{"type":"agent-extracted",
            "classes":[{"hash":"0123456789abcdef0123456789abcdef"}]}]
          """);
    }
    assertThatThrownBy(() -> DependencyDynamicRoots.scan(missing))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("Unresolved predefined class hash");
  }

  @Test
  void validatesNonRootForeignAndSerializationDenyDescriptors() throws IOException {
    final Path jar = tempDir.resolve("non-root-descriptors-" + System.nanoTime() + ".jar");
    try (JarOutputStream out = new JarOutputStream(Files.newOutputStream(jar))) {
      put(
          out,
          "META-INF/native-image/test/foreign-config.json",
          """
          {"downcalls":[{"descriptor":"(int,int)int",
            "options":{"firstVariadicArg":1,"captureCallState":true,"trivial":false}}]}
          """);
      put(out, "META-INF/native-image/test/empty/foreign-config.json", "{}");
      put(
          out,
          "META-INF/native-image/test/serialization-deny-config.json",
          """
          {"types":[{"name":"org.example.Denied",
            "customTargetConstructorClass":"org.example.DenyConstructor"}],
           "lambdaCapturingTypes":[],
           "proxies":[{"interfaces":["org.example.DeniedProxy"]}]}
          """);
      put(
          out,
          "META-INF/native-image/test/object-inlining-config.json",
          """
          {"value_fields":{"org.example.Inlined":["field"]},
           "value_field_types":{"org.example.FieldType":["prefix.*"]},
           "value_graph_types":{"org.example.GraphType":["!excluded.*","*"]}}
          """);
    }
    final DependencyDynamicRoots.RootScan scan = DependencyDynamicRoots.scan(jar);
    assertThat(scan.roots())
        .containsExactlyInAnyOrder(
            "org.example.Inlined", "org.example.FieldType", "org.example.GraphType");
  }

  private static void put(final JarOutputStream out, final String name, final String content)
      throws IOException {
    out.putNextEntry(new JarEntry(name));
    out.write(content.getBytes(StandardCharsets.UTF_8));
    out.closeEntry();
  }

  @Test
  void parsesNettyInitializeAtRunTimeAndBuildTimeRoots() throws IOException {
    final Path jar =
        nativeImageJarWithClasses(
            "Args = --initialize-at-build-time=io.netty \\\n"
                + "       --initialize-at-run-time=io.netty.handler.codec.http.HttpObjectEncoder,"
                + "io.netty.handler.codec.http.websocketx.WebSocket00FrameEncoder,"
                + "io.netty.handler.codec.http.websocketx.extensions.compression.DeflateDecoder\n",
            "io.netty.handler.codec.http.HttpObjectEncoder",
            "io.netty.handler.codec.http.websocketx.WebSocket00FrameEncoder",
            "io.netty.handler.codec.http.websocketx.extensions.compression.DeflateDecoder");

    final DependencyDynamicRoots.RootScan scan = DependencyDynamicRoots.scan(jar);

    assertThat(scan.roots())
        .contains(
            "io.netty.handler.codec.http.HttpObjectEncoder",
            "io.netty.handler.codec.http.websocketx.WebSocket00FrameEncoder",
            "io.netty.handler.codec.http.websocketx.extensions.compression.DeflateDecoder");
  }

  @Test
  void parsesNettyCompressionAndResolverDnsArgs() throws IOException {
    final Path compressionJar =
        nativeImageJarWithClasses(
            "Args = --initialize-at-run-time=io.netty.handler.codec.compression.BrotliDecoder\n",
            "io.netty.handler.codec.compression.BrotliDecoder");
    final DependencyDynamicRoots.RootScan compressionScan =
        DependencyDynamicRoots.scan(compressionJar);
    assertThat(compressionScan.roots())
        .contains("io.netty.handler.codec.compression.BrotliDecoder");

    final Path dnsJar =
        nativeImageJarWithClasses(
            "Args = --initialize-at-run-time=io.netty.resolver.dns."
                + "DefaultDnsServerAddressStreamProvider \\\n"
                + "       --initialize-at-run-time=io.netty.resolver.dns."
                + "DnsServerAddressStreamProviders$DefaultProviderHolder\n",
            "io.netty.resolver.dns.DefaultDnsServerAddressStreamProvider",
            "io.netty.resolver.dns.DnsServerAddressStreamProviders$DefaultProviderHolder");
    final DependencyDynamicRoots.RootScan dnsScan = DependencyDynamicRoots.scan(dnsJar);
    assertThat(dnsScan.roots())
        .contains(
            "io.netty.resolver.dns.DefaultDnsServerAddressStreamProvider",
            "io.netty.resolver.dns.DnsServerAddressStreamProviders$DefaultProviderHolder");
  }

  @Test
  void parsesNettyEpollResourceConditionWithTypeReachable() throws IOException {
    final String resourceConfig =
        "{\n"
            + "  \"resources\": {\n"
            + "    \"includes\": [\n"
            + "      {\n"
            + "        \"condition\": {\n"
            + "          \"typeReachable\": \"io.netty.channel.epoll.Native\"\n"
            + "        },\n"
            + "        \"pattern\": \".*libnetty_transport_native_epoll_.*\\\\.so\"\n"
            + "      }\n"
            + "    ]\n"
            + "  },\n"
            + "  \"bundles\": [{\"name\":\"org.example.Messages\",\n"
            + "    \"classNames\":[\"org.example.Message_fr\"]}]\n"
            + "}";

    final Path jar = tempDir.resolve("netty-epoll-" + System.nanoTime() + ".jar");
    try (JarOutputStream out = new JarOutputStream(Files.newOutputStream(jar))) {
      out.putNextEntry(
          new JarEntry(
              "META-INF/native-image/io.netty/netty-transport-classes-epoll/resource-config.json"));
      out.write(resourceConfig.getBytes(StandardCharsets.UTF_8));
      out.closeEntry();
    }

    final DependencyDynamicRoots.RootScan scan = DependencyDynamicRoots.scan(jar);

    assertThat(scan.roots())
        .contains("io.netty.channel.epoll.Native", "org.example.Message_fr")
        .doesNotContain("org.example.Messages");
  }

  @Test
  void acceptsStandaloneInitializeFlagsWithoutValue() throws IOException {
    final Path jar =
        nativeImageJar(
            "Args = --initialize-at-build-time --initialize-at-run-time "
                + "--report-unsupported-elements-at-runtime\n");

    final DependencyDynamicRoots.RootScan scan = DependencyDynamicRoots.scan(jar);

    assertThat(scan.roots()).isEmpty();
  }

  @Test
  void acceptsUnknownAndAuditedNoRootOptionsWithoutAddingRoots() throws IOException {
    final Path jar =
        nativeImageJar(
            "Args = -H:CustomUnknown=value -march=native --pgo --gc=G1 "
                + "-Dcustom.value=@file\n");

    final DependencyDynamicRoots.RootScan scan = DependencyDynamicRoots.scan(jar);

    assertThat(scan.roots()).isEmpty();
  }

  @Test
  void rejectsAuditedIndirectionsBeforeUnknownArgumentAcceptance() throws IOException {
    final List<String> indirections =
        List.of(
            "@args.txt",
            "-cp=deps/*",
            "-classpath",
            "--class-path=deps/*",
            "-p=modules",
            "--module-path=modules",
            "--add-modules=example.module",
            "--limit-modules=java.base",
            "-jar=application.jar",
            "-m=example.module/Main",
            "--module=example.module/Main",
            "--configurations-path=configs",
            "--exclude-config=config.json",
            "--bundle-apply=resource-config.json",
            "--language:js",
            "--tool:insight",
            "--macro:truffle",
            "-Vfeature=value",
            "-H:Module=example.module",
            "-J--class-path=deps/*",
            "-J--module-path=modules",
            "-J--upgrade-module-path=modules",
            "-J--patch-module=example.module=module.jar",
            "-J-Xbootclasspath/a:boot.jar",
            "-J-javaagent:agent.jar",
            "-J-agentlib:jdwp",
            "MainClass");

    for (final String argument : indirections) {
      final Path jar = nativeImageJar("Args = " + argument + "\n");
      assertThatThrownBy(() -> DependencyDynamicRoots.scan(jar))
          .as(argument)
          .isInstanceOf(IOException.class)
          .hasMessageContaining("native-image indirection");
    }
  }

  @Test
  void rejectsMalformedIndirectionFormsButAllowsNearMissOptions() throws IOException {
    final List<String> malformed =
        List.of(
            "@",
            "-cp",
            "--class-path=",
            "-p=",
            "--module-path=",
            "--add-modules=",
            "--limit-modules=",
            "-jar",
            "-m",
            "-m=",
            "-J--upgrade-module-path",
            "-J--upgrade-module-path=",
            "-J--upgrade-module-path:modules",
            "-J--patch-module",
            "-J--patch-module=",
            "-J--patch-module:example.module=module.jar",
            "-J-Xbootclasspath/a",
            "-J-Xbootclasspath/a:",
            "-J-Xbootclasspath/a=boot.jar",
            "--module=",
            "--configurations-path=",
            "--exclude-config=",
            "--bundle-apply",
            "--language:",
            "--tool:",
            "--macro:",
            "-V",
            "-V=bad",
            "-Vfeature=",
            "-H:Module=");
    for (final String argument : malformed) {
      final Path jar = nativeImageJar("Args = " + argument + "\n");
      assertThatThrownBy(() -> DependencyDynamicRoots.scan(jar))
          .as(argument)
          .isInstanceOf(IOException.class)
          .hasMessageContaining("native-image indirection");
    }

    final List<String> accepted =
        List.of(
            "--bundle-create",
            "-Version",
            "-march=native",
            "-pgo",
            "-mystery",
            "-J--upgrade-module-pathx=modules",
            "--pgo",
            "--gc=G1",
            "-J-Dcustom.value=@file",
            "-Dcustom.value=@file",
            "-H:UnknownFlag=value",
            "-H:IncludeResources=asset@name\\.dat");
    for (final String argument : accepted) {
      NativeImageIndirectionGuard.validate(argument);
    }
  }

  private Path nativeImageJar(final String args) throws IOException {
    return nativeImageJar(args, null, null);
  }

  private Path nativeImageJar(final String args, final String extraName, final String extraContent)
      throws IOException {
    final Path jar = tempDir.resolve("native-image-" + System.nanoTime() + ".jar");
    try (JarOutputStream out = new JarOutputStream(Files.newOutputStream(jar))) {
      out.putNextEntry(new JarEntry("META-INF/native-image/test/native-image.properties"));
      out.write(args.getBytes(StandardCharsets.UTF_8));
      out.closeEntry();
      if (extraName != null) {
        out.putNextEntry(new JarEntry(extraName));
        out.write(extraContent.getBytes(StandardCharsets.UTF_8));
        out.closeEntry();
      }
    }
    return jar;
  }

  private Path nativeImageJarWithClasses(final String args, final String... classNames)
      throws IOException {
    final Path jar = tempDir.resolve("native-image-classes-" + System.nanoTime() + ".jar");
    try (JarOutputStream out = new JarOutputStream(Files.newOutputStream(jar))) {
      put(out, "META-INF/native-image/test/native-image.properties", args);
      for (final String className : classNames) {
        put(out, className.replace('.', '/') + ".class", "class");
      }
    }
    return jar;
  }
}
