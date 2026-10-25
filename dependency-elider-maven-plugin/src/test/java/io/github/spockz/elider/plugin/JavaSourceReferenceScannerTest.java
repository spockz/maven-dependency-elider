// WHY: Proves javac attribution retains source dependencies for constants, generic bounds, and
// annotation types even when no runtime observation can reveal them.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.spockz.elider.engine.DependencyPruner;
import io.github.spockz.elider.engine.PruneConfig;
import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.ArtifactFileRef;
import io.github.spockz.elider.model.TraceData;
import io.github.spockz.elider.scanner.ArtifactClassIndex;
import io.github.spockz.elider.scanner.JarIndexScanner;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import java.util.stream.Stream;
import javax.tools.ToolProvider;
import org.apache.maven.execution.DefaultMavenExecutionRequest;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.model.Plugin;
import org.apache.maven.model.PluginManagement;
import org.apache.maven.project.MavenProject;
import org.apache.maven.toolchain.Toolchain;
import org.apache.maven.toolchain.ToolchainManager;
import org.codehaus.plexus.util.xml.Xpp3Dom;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

/** Verifies compiler-resolved source symbol extraction. */
@SuppressWarnings({
  "PMD.ExcessiveImports",
  "PMD.TooManyMethods",
  "PMD.CommentDefaultAccessModifier",
  "PMD.UnitTestContainsTooManyAsserts",
  "PMD.AvoidDuplicateLiterals",
  "PMD.UseConcurrentHashMap",
  "PMD.LiteralsFirstInComparisons",
  "PMD.UseExplicitTypes",
  "PMD.AvoidInstantiatingObjectsInLoops"
})
final class JavaSourceReferenceScannerTest {
  /** Isolated source, compiler output, and JAR paths for each test. */
  @TempDir private Path tempDir;

  /** Creates the isolated scanner fixture. */
  JavaSourceReferenceScannerTest() {
    super();
  }

  @Test
  void findsConstantOwnersGenericBoundsAndAnnotationTypes() throws IOException {
    final Path dependencyJar = compileDependencyJar();
    final Path sourceRoot = Files.createDirectories(tempDir.resolve("app-src"));
    final Path source = sourceRoot.resolve("app/Example.java");
    Files.createDirectories(source.getParent());
    Files.writeString(
        source,
        "package app;\n"
            + "import static library.Constants.TEXT;\n"
            + "@library.Marker\n"
            + "final class Example<T extends library.GenericBound> {\n"
            + "  static final String COPY = TEXT;\n"
            + "}\n");

    final Set<String> references =
        new JavaSourceReferenceScanner()
            .scan(
                List.of(sourceRoot.toString()),
                List.of(dependencyJar.toString()),
                List.of("--release", "21"));
    final Path consumerClasses = Files.createDirectories(tempDir.resolve("consumer-classes"));
    final int compilationResult =
        ToolProvider.getSystemJavaCompiler()
            .run(
                null,
                null,
                null,
                "--release",
                "21",
                "-classpath",
                dependencyJar.toString(),
                "-d",
                consumerClasses.toString(),
                source.toString());
    if (compilationResult != 0) {
      throw new IOException("Could not compile the source-reference fixture");
    }
    final boolean[] containsConstantValue = {false};
    final boolean[] referencesConstantField = {false};
    new ClassReader(Files.readAllBytes(consumerClasses.resolve("app/Example.class")))
        .accept(
            new ClassVisitor(Opcodes.ASM9) {
              @Override
              public org.objectweb.asm.FieldVisitor visitField(
                  final int access,
                  final String name,
                  final String descriptor,
                  final String signature,
                  final Object value) {
                if (name.equals("COPY") && "inlined".equals(value)) {
                  containsConstantValue[0] = true;
                }
                return super.visitField(access, name, descriptor, signature, value);
              }

              @Override
              public MethodVisitor visitMethod(
                  final int access,
                  final String name,
                  final String descriptor,
                  final String signature,
                  final String[] exceptions) {
                return new MethodVisitor(Opcodes.ASM9) {
                  @Override
                  public void visitFieldInsn(
                      final int opcode,
                      final String owner,
                      final String fieldName,
                      final String fieldDescriptor) {
                    if (owner.equals("library/Constants")) {
                      referencesConstantField[0] = true;
                    }
                  }
                };
              }
            },
            0);
    final ArtifactFileRef constantOwner =
        ArtifactFileRef.fromPath(
            new ArtifactCoordinate("org.example", "compiler-visible", "1.0", "jar", "", "compile"),
            dependencyJar);
    final ArtifactFileRef runtimeOwner =
        new ArtifactFileRef(
            new ArtifactCoordinate("org.example", "runtime", "1.0", "jar", "", "compile"),
            tempDir.resolve("runtime.jar"),
            0,
            0);
    final Map<ArtifactFileRef, Set<String>> indexedClasses =
        new java.util.HashMap<>(
            new JarIndexScanner().scan(List.of(constantOwner)).classesByArtifact());
    indexedClasses.put(runtimeOwner, Set.of("app.RuntimeEntry"));
    final var decision =
        new DependencyPruner()
            .prune(
                List.of(constantOwner, runtimeOwner),
                new ArtifactClassIndex(indexedClasses),
                TraceData.of(Set.of("app.RuntimeEntry")),
                new PruneConfig(),
                references);

    assertThat(references).contains("library.Constants", "library.GenericBound", "library.Marker");
    assertThat(containsConstantValue[0]).isTrue();
    assertThat(referencesConstantField[0]).isFalse();
    assertThat(decision.retainedArtifacts())
        .containsExactlyInAnyOrder(constantOwner.coordinate(), runtimeOwner.coordinate());
    assertThat(decision.getRetainedClasses(constantOwner.coordinate()))
        .containsExactlyInAnyOrder("library.Constants", "library.GenericBound", "library.Marker");
  }

  @Test
  void failsExplicitlyWhenProductionTypeCannotBeResolved() throws IOException {
    final Path sourceRoot = Files.createDirectories(tempDir.resolve("broken-src"));
    final Path source = sourceRoot.resolve("app/Broken.java");
    Files.createDirectories(source.getParent());
    Files.writeString(source, "package app; final class Broken { missing.Type field; }\n");

    assertThatThrownBy(
            () ->
                new JavaSourceReferenceScanner()
                    .scan(List.of(sourceRoot.toString()), List.of(), List.of("--release", "21")))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("Cannot resolve production source references");
  }

  @Test
  void honorsPluginReleaseInsteadOfConflictingCompilerProperty() throws IOException {
    final MavenProject project = new MavenProject();
    project.getProperties().setProperty("maven.compiler.release", "21");
    final Xpp3Dom configuration = new Xpp3Dom("configuration");
    final Xpp3Dom release = new Xpp3Dom("release");
    release.setValue("17");
    configuration.addChild(release);
    project.getBuild().addPlugin(compilerPlugin(configuration));

    assertThat(MavenCompilerSettings.options(project, null, List.of()))
        .containsExactly("--release", "17");
  }

  @Test
  void honorsPluginSourceAndTargetSettings() throws IOException {
    final MavenProject project = new MavenProject();
    final Xpp3Dom configuration = new Xpp3Dom("configuration");
    final Xpp3Dom source = new Xpp3Dom("source");
    source.setValue("11");
    final Xpp3Dom target = new Xpp3Dom("target");
    target.setValue("11");
    configuration.addChild(source);
    configuration.addChild(target);
    project.getBuild().addPlugin(compilerPlugin(configuration));

    assertThat(MavenCompilerSettings.options(project, null, List.of()))
        .containsExactly("-source", "11", "-target", "11");
  }

  @Test
  void rejectsConflictingReleaseAndSourceTargetConfiguration() {
    final MavenProject project = new MavenProject();
    project.getProperties().setProperty("maven.compiler.release", "21");
    final Xpp3Dom configuration = new Xpp3Dom("configuration");
    final Xpp3Dom source = new Xpp3Dom("source");
    source.setValue("11");
    final Xpp3Dom target = new Xpp3Dom("target");
    target.setValue("11");
    configuration.addChild(source);
    configuration.addChild(target);
    project.getBuild().addPlugin(compilerPlugin(configuration));

    assertThatThrownBy(() -> MavenCompilerSettings.options(project, null, List.of()))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("both compiler release and source/target");
  }

  @Test
  void rejectsPreviewCompilerModeThatAttributionCannotMirror() {
    final MavenProject project = new MavenProject();
    final Xpp3Dom configuration = new Xpp3Dom("configuration");
    final Xpp3Dom preview = new Xpp3Dom("enablePreview");
    preview.setValue("true");
    configuration.addChild(preview);
    project.getBuild().addPlugin(compilerPlugin(configuration));
    project.getProperties().setProperty("maven.compiler.release", "21");

    assertThatThrownBy(() -> MavenCompilerSettings.options(project, null, List.of()))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("configured compiler mode");
  }

  @Test
  void rejectsLegacyCompilerArgumentsConfiguration() {
    final MavenProject project = new MavenProject();
    final Xpp3Dom configuration = new Xpp3Dom("configuration");
    final Xpp3Dom compilerArguments = new Xpp3Dom("compilerArguments");
    final Xpp3Dom sourcepath = new Xpp3Dom("sourcepath");
    sourcepath.setValue("generated-sources");
    compilerArguments.addChild(sourcepath);
    configuration.addChild(compilerArguments);
    project.getBuild().addPlugin(compilerPlugin(configuration));
    project.getProperties().setProperty("maven.compiler.release", "21");

    assertThatThrownBy(() -> MavenCompilerSettings.options(project, null, List.of()))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("compiler setting compilerArguments");
  }

  @Test
  void rejectsCompilerArgumentsFromPluginManagement() {
    final MavenProject project = new MavenProject();
    final Xpp3Dom configuration = new Xpp3Dom("configuration");
    final Xpp3Dom compilerArguments = new Xpp3Dom("compilerArguments");
    final Xpp3Dom sourcepath = new Xpp3Dom("sourcepath");
    sourcepath.setValue("generated-sources");
    compilerArguments.addChild(sourcepath);
    configuration.addChild(compilerArguments);
    final PluginManagement pluginManagement = new PluginManagement();
    pluginManagement.addPlugin(compilerPlugin(configuration));
    project.getBuild().setPluginManagement(pluginManagement);
    project.getProperties().setProperty("maven.compiler.release", "21");

    assertThatThrownBy(() -> MavenCompilerSettings.options(project, null, List.of()))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("compiler setting compilerArguments");
  }

  @Test
  void rejectsForkedAndNonJavacPluginModes() {
    assertPluginCompilerSettingRejected("fork", "true");
    assertPluginCompilerSettingRejected("compilerId", "ecj");
    assertPluginCompilerSettingRejected("executable", "/custom/javac");
  }

  @Test
  void rejectsUnsupportedMavenSessionCompilerProperties() {
    assertSessionCompilerPropertyRejected("maven.compiler.fork", "true");
    assertSessionCompilerPropertyRejected("maven.compiler.compilerId", "ecj");
    assertSessionCompilerPropertyRejected("maven.compiler.executable", "/custom/javac");
    assertSessionCompilerPropertyRejected("maven.compiler.enablePreview", "true");
    assertSessionCompilerPropertyRejected("maven.compiler.jdkToolchain", "jdk-17");
  }

  @Test
  void acceptsExplicitlySafeCompilerModeProperties() throws IOException {
    final Properties properties = new Properties();
    properties.setProperty("maven.compiler.fork", "false");
    properties.setProperty("maven.compiler.enablePreview", "false");
    properties.setProperty("maven.compiler.useModulePath", "false");
    properties.setProperty("maven.compiler.compilerId", "javac");

    assertThatCode(
            () ->
                MavenCompilerSettings.rejectUnsupportedSettings(
                    List.of(), properties, new Properties()))
        .doesNotThrowAnyException();
  }

  private Path compileDependencyJar() throws IOException {
    final Path sourceRoot = Files.createDirectories(tempDir.resolve("dependency-src/library"));
    final Path output = Files.createDirectories(tempDir.resolve("dependency-classes"));
    Files.writeString(
        sourceRoot.resolve("Constants.java"),
        "package library; public final class Constants { "
            + "public static final String TEXT = \"inlined\"; }\n");
    Files.writeString(
        sourceRoot.resolve("GenericBound.java"),
        "package library; public interface GenericBound {}\n");
    Files.writeString(
        sourceRoot.resolve("Marker.java"), "package library; public @interface Marker {}\n");
    final int result =
        ToolProvider.getSystemJavaCompiler()
            .run(
                null,
                null,
                null,
                "--release",
                "21",
                "-d",
                output.toString(),
                sourceRoot.resolve("Constants.java").toString(),
                sourceRoot.resolve("GenericBound.java").toString(),
                sourceRoot.resolve("Marker.java").toString());
    if (result != 0) {
      throw new IOException("Could not compile test dependency sources");
    }
    final Path jar = tempDir.resolve("compiler-visible.jar");
    try (JarOutputStream archive = new JarOutputStream(Files.newOutputStream(jar));
        Stream<Path> paths = Files.walk(output)) {
      for (final Path classFile : paths.filter(Files::isRegularFile).toList()) {
        archive.putNextEntry(
            new JarEntry(output.relativize(classFile).toString().replace('\\', '/')));
        Files.copy(classFile, archive);
        archive.closeEntry();
      }
    }
    return jar;
  }

  private static Plugin compilerPlugin(final Xpp3Dom configuration) {
    final Plugin compiler = new Plugin();
    compiler.setGroupId("org.apache.maven.plugins");
    compiler.setArtifactId("maven-compiler-plugin");
    compiler.setConfiguration(configuration);
    return compiler;
  }

  private static void assertSessionCompilerPropertyRejected(
      final String propertyName, final String value) {
    final MavenProject project = new MavenProject();
    project.getProperties().setProperty("maven.compiler.release", "21");
    final Properties userProperties = new Properties();
    userProperties.setProperty(propertyName, value);
    final MavenSession session = new TestMavenSession(project, userProperties);

    assertThatThrownBy(() -> MavenCompilerSettings.options(project, session, List.of()))
        .isInstanceOf(IOException.class)
        .hasMessageContaining(propertyName);
  }

  private static void assertPluginCompilerSettingRejected(final String name, final String value) {
    final MavenProject project = new MavenProject();
    project.getProperties().setProperty("maven.compiler.release", "21");
    final Xpp3Dom configuration = new Xpp3Dom("configuration");
    final Xpp3Dom setting = new Xpp3Dom(name);
    setting.setValue(value);
    configuration.addChild(setting);
    project.getBuild().addPlugin(compilerPlugin(configuration));

    assertThatThrownBy(() -> MavenCompilerSettings.options(project, null, List.of()))
        .isInstanceOf(IOException.class);
  }

  /** Supplies stable compiler user properties and an empty selected-toolchain lookup. */
  @SuppressWarnings("PMD.TestClassWithoutTestCases")
  private static final class TestMavenSession extends MavenSession {
    /** Session-level compiler settings for the test. */
    private final Properties userProperties;

    /** Toolchain service that reports no selected toolchain. */
    private final ToolchainManager toolchainManager =
        new ToolchainManager() {
          @Override
          public Toolchain getToolchainFromBuildContext(
              final String type, final MavenSession session) {
            return null;
          }

          @Override
          public List<Toolchain> getToolchains(
              final MavenSession session,
              final String type,
              final Map<String, String> requirements) {
            return List.of();
          }
        };

    private TestMavenSession(final MavenProject project, final Properties userProperties) {
      super(null, new DefaultMavenExecutionRequest(), null, project);
      this.userProperties = userProperties;
    }

    @Override
    public Properties getUserProperties() {
      return userProperties;
    }

    @Override
    public Object lookup(final String role) {
      return toolchainManager;
    }
  }
}
