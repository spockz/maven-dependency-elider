/* WHY: Captures selected standard system modules once per analysis context so cache
 * identity and ProGuard platform classes share the same parsed class resources. */

package io.github.spockz.elider.trimmer;

import io.github.spockz.elider.model.ArtifactDigests;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.lang.module.Configuration;
import java.lang.module.FindException;
import java.lang.module.ModuleDescriptor;
import java.lang.module.ModuleFinder;
import java.lang.module.ModuleReader;
import java.lang.module.ModuleReference;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import proguard.classfile.ClassPool;
import proguard.classfile.LibraryClass;

/** Owns one active-runtime platform snapshot for an analysis context. */
@SuppressWarnings({
  "PMD.CouplingBetweenObjects",
  "PMD.TooManyMethods",
  "PMD.CommentDefaultAccessModifier",
  "PMD.AvoidSynchronizedAtMethodLevel",
  "PMD.GodClass"
})
public final class JdkPlatformContext implements AutoCloseable {
  /** Changes when system-module selection or runtime-class interpretation changes. */
  public static final String READER_POLICY_VERSION = "jdk-runtime-module-reader-v2";

  /** Cached immutable snapshot for the active JVM's system modules. */
  private static PlatformSnapshot cachedSystemSnapshot;

  /** Standard runtime module finder for this snapshot. */
  private final ModuleFinder moduleFinder;

  /** Whether this context targets the JVM's immutable active system modules. */
  private final boolean systemRuntime;

  /** Version and implementation attached to the captured modules. */
  private final RuntimeMetadata runtimeMetadata;

  /** Cached snapshot; cleared on close to release parsed class templates. */
  private PlatformSnapshot capturedSnapshot;

  /** Whether this owner has released its snapshot. */
  private boolean closed;

  /** Serializes snapshot capture and close so one complete snapshot is published. */
  private final Lock lifecycleLock = new ReentrantLock();

  /** Creates an identity owner for the active JVM's system modules. */
  public JdkPlatformContext() {
    this(ModuleFinder.ofSystem(), true);
  }

  JdkPlatformContext(final ModuleFinder moduleFinder) {
    this(moduleFinder, false);
  }

  private JdkPlatformContext(final ModuleFinder moduleFinder, final boolean systemRuntime) {
    this(moduleFinder, systemRuntime, RuntimeMetadata.active());
  }

  private JdkPlatformContext(
      final ModuleFinder moduleFinder,
      final boolean systemRuntime,
      final RuntimeMetadata metadata) {
    this.moduleFinder = Objects.requireNonNull(moduleFinder, "moduleFinder");
    this.systemRuntime = systemRuntime;
    this.runtimeMetadata = metadata;
  }

  /** Captures declarations and module descriptors from an explicit runtime. */
  public static PlatformSnapshot inspectRuntime(final Path input) throws IOException {
    return inspectRuntime(input, null);
  }

  /** Captures an explicit runtime with an optional index directory. */
  public static PlatformSnapshot inspectRuntime(final Path input, final Path indexDirectory)
      throws IOException {
    final Path active = Path.of(System.getProperty("java.home"));
    if (java.nio.file.Files.isDirectory(input) && java.nio.file.Files.isSameFile(input, active)) {
      try (JdkPlatformContext context = new JdkPlatformContext()) {
        return context.snapshot();
      }
    }
    return RuntimeImageReader.inspect(input, indexDirectory);
  }

  /** An in-process tool that needs an installed Java home for its system image. */
  @FunctionalInterface
  public interface RuntimeTool<T> {
    /** Runs the tool while the temporary home is valid. */
    T use(Path javaHome) throws IOException;
  }

  /** Runs a tool against selected modules using the executing JDK's JRT reader. */
  public static <T> T withInstalledRuntimeForTool(final Path input, final RuntimeTool<T> tool)
      throws IOException {
    return RuntimeImageReader.withInstalledRuntimeForTool(input, tool);
  }

  /* package */ static PlatformSnapshot inspectModules(
      final ModuleFinder finder, final RuntimeMetadata metadata, final String imageDigest)
      throws IOException {
    try (JdkPlatformContext context = new JdkPlatformContext(finder, false, metadata)) {
      return context.captureRuntimePlatform(imageDigest);
    }
  }

  private static synchronized PlatformSnapshot getOrCaptureSystemSnapshot(
      final JdkPlatformContext context) throws IOException {
    if (cachedSystemSnapshot == null) {
      cachedSystemSnapshot = context.captureRuntimePlatform();
    }
    return cachedSystemSnapshot;
  }

  /** Captures or returns the active runtime's standard platform modules. */
  public PlatformSnapshot snapshot() throws IOException {
    lifecycleLock.lock();
    try {
      ensureOpen();
      if (capturedSnapshot == null) {
        capturedSnapshot =
            systemRuntime ? getOrCaptureSystemSnapshot(this) : captureRuntimePlatform();
      }
      return capturedSnapshot;
    } finally {
      lifecycleLock.unlock();
    }
  }

  /** Releases the parsed templates owned by this context. */
  @Override
  @SuppressWarnings("PMD.NullAssignment")
  public void close() {
    lifecycleLock.lock();
    try {
      closed = true;
      capturedSnapshot = null;
    } finally {
      lifecycleLock.unlock();
    }
  }

  private PlatformSnapshot captureRuntimePlatform() throws IOException {
    return captureRuntimePlatform(null);
  }

  private PlatformSnapshot captureRuntimePlatform(final String imageDigest) throws IOException {
    final List<ModuleReference> modules = systemModules();
    if (modules.isEmpty()) {
      throw new IOException("The active JDK exposes no standard system modules");
    }
    final List<CapturedModule> capturedModules = captureModules(modules);
    return new PlatformSnapshot(
        runtimeMetadata,
        capturedModules,
        modules.stream().map(ModuleReference::descriptor).toList(),
        imageDigest);
  }

  private static List<CapturedModule> captureModules(final List<ModuleReference> modules)
      throws IOException {
    try {
      return modules.parallelStream().map(JdkPlatformContext::captureModuleUnchecked).toList();
    } catch (final UncheckedIOException exception) {
      throw new IOException(exception.getMessage(), exception);
    }
  }

  private static CapturedModule captureModuleUnchecked(final ModuleReference module) {
    try {
      return captureModule(module);
    } catch (final IOException exception) {
      throw new UncheckedIOException(exception.getMessage(), exception);
    }
  }

  private List<ModuleReference> systemModules() throws IOException {
    try {
      return moduleFinder.findAll().stream()
          .sorted(Comparator.comparing(reference -> reference.descriptor().name()))
          .toList();
    } catch (final FindException | SecurityException exception) {
      throw new IOException("Could not locate the active runtime's standard modules", exception);
    }
  }

  private static CapturedModule captureModule(final ModuleReference module) throws IOException {
    final ModuleDescriptor descriptor = module.descriptor();
    final MessageDigest digest = ArtifactDigests.newSha256Digest();
    updateDescriptor(digest, descriptor);
    long classBytes = 0;
    long classCount = 0;
    String descriptorBytes = null;
    final JdkApiClassTableReader.ClassDeclarationCollector collector =
        JdkApiClassTableReader.newDeclarationCollector();
    final List<LibraryClass> classes;
    try (ModuleReader reader = module.open()) {
      final List<String> resources = classResources(reader, descriptor.name());
      classes = new ArrayList<>(resources.size());
      for (final String resource : resources) {
        final byte[] bytes = readResource(reader, resource, descriptor.name());
        updateResource(digest, resource, bytes);
        classBytes += bytes.length;
        final LibraryClass parsed =
            JdkApiClassTableReader.parseModuleClass(bytes, resource, descriptor.name(), collector);
        if (parsed != null) {
          classes.add(parsed);
        }
        if (moduleInfo(resource)) {
          descriptorBytes = java.util.Base64.getEncoder().encodeToString(bytes);
        } else {
          classCount++;
        }
      }
    }
    return new CapturedModule(
        new ModuleIdentity(
            descriptor.name(), classCount, classBytes, HexFormat.of().formatHex(digest.digest())),
        descriptorBytes,
        classes);
  }

  record CapturedModule(
      ModuleIdentity identity, String descriptorBytes, List<LibraryClass> classes) {}

  private static List<String> classResources(final ModuleReader reader, final String moduleName)
      throws IOException {
    try (Stream<String> resources = reader.list()) {
      return resources.filter(name -> name.endsWith(".class")).sorted().toList();
    } catch (final UncheckedIOException exception) {
      throw new IOException("Could not list classes in runtime module " + moduleName, exception);
    }
  }

  private static byte[] readResource(
      final ModuleReader reader, final String resource, final String moduleName)
      throws IOException {
    final Optional<InputStream> opened = reader.open(resource);
    if (opened.isEmpty()) {
      throw new IOException(
          "Runtime module listed but could not open class " + moduleName + "/" + resource);
    }
    try (InputStream input = opened.orElseThrow()) {
      return input.readAllBytes();
    }
  }

  private static boolean moduleInfo(final String resource) {
    return "module-info.class".equals(resource) || resource.endsWith("/module-info.class");
  }

  private static void updateDescriptor(
      final MessageDigest digest, final ModuleDescriptor descriptor) {
    updateString(digest, "module");
    updateString(digest, descriptor.name());
    updateString(digest, descriptor.rawVersion().orElse(""));
    updateStrings(digest, "modifier", descriptor.modifiers().stream().map(Enum::name).toList());
    updateStrings(digest, "package", descriptor.packages().stream().sorted().toList());
    descriptor.requires().stream()
        .sorted(Comparator.comparing(ModuleDescriptor.Requires::name))
        .forEach(
            requires -> {
              updateString(digest, "requires");
              updateString(digest, requires.name());
              updateStrings(
                  digest,
                  "requires-modifier",
                  requires.modifiers().stream().map(Enum::name).toList());
              updateString(
                  digest,
                  requires.compiledVersion().map(ModuleDescriptor.Version::toString).orElse(""));
            });
    descriptor.exports().stream()
        .sorted(Comparator.comparing(ModuleDescriptor.Exports::source))
        .forEach(
            exports -> {
              updateString(digest, "exports");
              updateString(digest, exports.source());
              updateStrings(
                  digest,
                  "exports-modifier",
                  exports.modifiers().stream().map(Enum::name).toList());
              updateStrings(digest, "exports-target", exports.targets().stream().sorted().toList());
            });
    descriptor.opens().stream()
        .sorted(Comparator.comparing(ModuleDescriptor.Opens::source))
        .forEach(
            opens -> {
              updateString(digest, "opens");
              updateString(digest, opens.source());
              updateStrings(
                  digest, "opens-modifier", opens.modifiers().stream().map(Enum::name).toList());
              updateStrings(digest, "opens-target", opens.targets().stream().sorted().toList());
            });
    updateStrings(digest, "uses", descriptor.uses().stream().sorted().toList());
    descriptor.provides().stream()
        .sorted(Comparator.comparing(ModuleDescriptor.Provides::service))
        .forEach(
            provides -> {
              updateString(digest, "provides");
              updateString(digest, provides.service());
              updateStrings(digest, "provider", provides.providers().stream().sorted().toList());
            });
  }

  private static void updateResource(
      final MessageDigest digest, final String resource, final byte[] bytes) {
    updateString(digest, "class-resource");
    updateString(digest, resource);
    updateLong(digest, bytes.length);
    digest.update(bytes);
  }

  private static void updateStrings(
      final MessageDigest digest, final String label, final List<String> values) {
    updateString(digest, label);
    updateLong(digest, values.size());
    values.stream().sorted().forEach(value -> updateString(digest, value));
  }

  private static void updateString(final MessageDigest digest, final String value) {
    final byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
    updateLong(digest, bytes.length);
    digest.update(bytes);
  }

  private static void updateLong(final MessageDigest digest, final long value) {
    digest.update(ByteBuffer.allocate(Long.BYTES).putLong(value).array());
  }

  private void ensureOpen() {
    if (closed) {
      throw new IllegalStateException("JDK platform context is closed");
    }
  }

  /** Compact content identity for one active runtime module. */
  public record ModuleIdentity(String moduleName, long classCount, long byteCount, String sha256) {}

  /** Version and available implementation details from the inspected image. */
  public record RuntimeMetadata(
      Runtime.Version version,
      String vendor,
      String implementation,
      String operatingSystem,
      String architecture) {
    static RuntimeMetadata active() {
      return new RuntimeMetadata(
          Runtime.version(),
          System.getProperty("java.vendor"),
          System.getProperty("java.vm.name"),
          System.getProperty("os.name"),
          System.getProperty("os.arch"));
    }
  }

  /** Immutable runtime module selection and parsed class templates. */
  public static final class PlatformSnapshot {
    /** Metadata read from the inspected runtime. */
    private final RuntimeMetadata identityMetadata;

    /** Module identity records in module-name order. */
    private final List<ModuleIdentity> modules;

    /** Descriptors consumed by selected-system-module resolution. */
    private final List<ModuleDescriptor> descriptors;

    /** Captured declarations by module for named-application resolution. */
    private final List<CapturedModule> captured;

    /** Parsed ProGuard declarations used as templates for independent class tables. */
    private final FrozenClassPool jdkClassTable;

    /** Deterministic identity for this runtime and its system-module contents. */
    private final String platformIdentity;

    private PlatformSnapshot(
        final RuntimeMetadata metadata,
        final List<CapturedModule> captured,
        final List<ModuleDescriptor> descriptors,
        final String parentIdentity)
        throws IOException {
      this.identityMetadata = metadata;
      this.captured = List.copyOf(captured);
      this.modules = captured.stream().map(CapturedModule::identity).toList();
      this.descriptors = List.copyOf(descriptors);
      this.jdkClassTable =
          JdkApiClassTableReader.populateClassTable(
              captured.stream().map(CapturedModule::classes).toList());
      final StringBuilder value =
          new StringBuilder(128)
              .append("platform-source=jrt\nreader=")
              .append(READER_POLICY_VERSION)
              .append("\nruntime=")
              .append(metadata)
              .append('\n');
      if (parentIdentity != null) {
        value
            .append("image-sha256=")
            .append(io.github.spockz.elider.model.HexDigest.sha256(parentIdentity))
            .append('\n');
      }
      for (final ModuleIdentity module : this.modules) {
        value
            .append("module=")
            .append(module.moduleName())
            .append(':')
            .append(module.classCount())
            .append(':')
            .append(module.byteCount())
            .append(':')
            .append(module.sha256())
            .append('\n');
      }
      platformIdentity = value.toString();
    }

    /** Returns the inspected runtime feature release. */
    public int runtimeRelease() {
      return runtimeVersion().feature();
    }

    /** Returns the inspected runtime version, including a build when available. */
    public Runtime.Version runtimeVersion() {
      return identityMetadata.version();
    }

    /** Returns the runtime version and implementation as recorded by the image. */
    public RuntimeMetadata metadata() {
      return identityMetadata;
    }

    /** Returns the selected image's standard module descriptors. */
    public List<ModuleDescriptor> moduleDescriptors() {
      return descriptors;
    }

    /** Resolves an application using only modules from this image. */
    public PlatformSnapshot forApplicationModule(final ModuleDescriptor application)
        throws IOException {
      final ModuleFinder runtime = RuntimeModuleFinder.descriptors(descriptors);
      if (runtime.find(application.name()).isPresent()) {
        throw new IOException("Application module shadows a runtime module: " + application.name());
      }
      final ModuleFinder finder =
          ModuleFinder.compose(RuntimeModuleFinder.descriptors(List.of(application)), runtime);
      final Set<String> included;
      try {
        included =
            Configuration.empty()
                .resolveAndBind(finder, ModuleFinder.of(), Set.of(application.name()))
                .modules()
                .stream()
                .map(java.lang.module.ResolvedModule::name)
                .filter(name -> !name.equals(application.name()))
                .collect(Collectors.toUnmodifiableSet());
      } catch (final FindException | java.lang.module.ResolutionException exception) {
        throw new IOException(
            "Selected runtime cannot resolve application module "
                + application.name()
                + ": "
                + exception.getMessage(),
            exception);
      }
      return included.size() == descriptors.size()
          ? this
          : new PlatformSnapshot(
              identityMetadata,
              captured.stream()
                  .filter(module -> included.contains(module.identity().moduleName()))
                  .toList(),
              descriptors.stream().filter(module -> included.contains(module.name())).toList(),
              platformIdentity);
    }

    /** Returns the descriptive source kind for this active runtime platform. */
    public String sourceKind() {
      return "jrt";
    }

    /** Returns deterministic module-level identities for all system modules. */
    public List<ModuleIdentity> moduleIdentities() {
      return List.copyOf(modules);
    }

    /** Returns the deterministic content identity used by the trim fingerprint. */
    public String identity() {
      return platformIdentity;
    }

    List<CapturedModule> capturedModules() {
      return List.copyOf(captured);
    }

    static PlatformSnapshot fromIndex(
        final RuntimeMetadata metadata,
        final List<CapturedModule> modules,
        final List<ModuleDescriptor> moduleDescriptors,
        final String imageDigest)
        throws IOException {
      return new PlatformSnapshot(metadata, modules, moduleDescriptors, imageDigest);
    }

    ClassPool classTableTemplate() {
      return jdkClassTable;
    }
  }
}
