/* WHY: Captures the active runtime's standard system modules once per analysis context so cache
 * identity and ProGuard platform classes share the same parsed class resources. */

package io.github.spockz.elider.trimmer;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.lang.module.FindException;
import java.lang.module.ModuleDescriptor;
import java.lang.module.ModuleFinder;
import java.lang.module.ModuleReader;
import java.lang.module.ModuleReference;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;
import java.util.stream.Stream;
import org.objectweb.asm.ClassReader;
import proguard.classfile.ClassPool;

/** Owns one active-runtime platform snapshot for an analysis context. */
@SuppressWarnings({"PMD.TooManyMethods", "PMD.CommentDefaultAccessModifier"})
public final class JdkPlatformContext implements AutoCloseable {
  /** Changes when system-module selection or runtime-class interpretation changes. */
  public static final String READER_POLICY_VERSION = "jdk-runtime-module-reader-v1";

  /** Standard runtime module finder for this snapshot. */
  private final ModuleFinder moduleFinder;

  /** Cached snapshot; cleared on close to release parsed class templates. */
  private PlatformSnapshot capturedSnapshot;

  /** Whether this owner has released its snapshot. */
  private boolean closed;

  /** Serializes snapshot capture and close so one complete snapshot is published. */
  private final Lock lifecycleLock = new ReentrantLock();

  /** Creates an identity owner for the active JVM's system modules. */
  public JdkPlatformContext() {
    this(ModuleFinder.ofSystem());
  }

  JdkPlatformContext(final ModuleFinder moduleFinder) {
    this.moduleFinder = Objects.requireNonNull(moduleFinder, "moduleFinder");
  }

  /** Captures or returns the active runtime's standard platform modules. */
  public PlatformSnapshot snapshot() throws IOException {
    lifecycleLock.lock();
    try {
      ensureOpen();
      if (capturedSnapshot == null) {
        capturedSnapshot = captureRuntimePlatform();
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
    final List<ModuleReference> modules = systemModules();
    if (modules.isEmpty()) {
      throw new IOException("The active JDK exposes no standard system modules");
    }
    final ClassPool jdkClassTable = new ClassPool();
    final List<ModuleIdentity> identities = new ArrayList<>(modules.size());
    for (final ModuleReference module : modules) {
      identities.add(captureModule(module, jdkClassTable));
    }
    if (jdkClassTable.getClass("java/lang/Object") == null) {
      throw new IOException("The active runtime platform does not contain java/lang/Object");
    }
    return new PlatformSnapshot(Runtime.version().feature(), identities, jdkClassTable);
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

  private static ModuleIdentity captureModule(
      final ModuleReference module, final ClassPool jdkClassTable) throws IOException {
    final ModuleDescriptor descriptor = module.descriptor();
    final MessageDigest digest = sha256();
    updateDescriptor(digest, descriptor);
    long classBytes = 0;
    long classCount = 0;
    try (ModuleReader reader = module.open()) {
      final List<String> resources = classResources(reader, descriptor.name());
      for (final String resource : resources) {
        final byte[] bytes = readResource(reader, resource, descriptor.name());
        updateResource(digest, resource, bytes);
        classBytes += bytes.length;
        addClass(bytes, resource, descriptor.name(), jdkClassTable);
        if (!moduleInfo(resource)) {
          classCount++;
        }
      }
    }
    return new ModuleIdentity(
        descriptor.name(), classCount, classBytes, HexFormat.of().formatHex(digest.digest()));
  }

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

  private static void addClass(
      final byte[] bytes,
      final String resource,
      final String moduleName,
      final ClassPool jdkClassTable)
      throws IOException {
    final ClassReader reader;
    try {
      reader = new ClassReader(bytes);
      if (moduleInfo(resource)) {
        return;
      }
      final String expectedName = resource.substring(0, resource.length() - ".class".length());
      final String actualName = reader.getClassName();
      if (!expectedName.equals(actualName)) {
        throw new IOException(
            "Runtime module class path does not match name: " + moduleName + "/" + resource);
      }
      if (jdkClassTable.getClass(actualName) != null) {
        throw new IOException("Duplicate active runtime class in system modules: " + actualName);
      }
      JdkApiClassTableReader.addLibraryClass(reader, jdkClassTable);
    } catch (final IllegalArgumentException | IndexOutOfBoundsException exception) {
      throw new IOException(
          "Could not parse runtime module class: " + moduleName + "/" + resource, exception);
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

  private static MessageDigest sha256() {
    try {
      return MessageDigest.getInstance("SHA-256");
    } catch (final NoSuchAlgorithmException exception) {
      throw new IllegalStateException("Required SHA-256 digest is unavailable", exception);
    }
  }

  private void ensureOpen() {
    if (closed) {
      throw new IllegalStateException("JDK platform context is closed");
    }
  }

  /** Compact content identity for one active runtime module. */
  public record ModuleIdentity(String moduleName, long classCount, long byteCount, String sha256) {}

  /** Immutable active-runtime module selection and parsed class templates. */
  public static final class PlatformSnapshot {
    /** Active runtime feature release. */
    private final int activeRuntimeFeature;

    /** Module identity records in module-name order. */
    private final List<ModuleIdentity> modules;

    /** Parsed ProGuard declarations used as templates for independent class tables. */
    private final ClassPool jdkClassTable;

    /** Deterministic identity for this runtime and its system-module contents. */
    private final String platformIdentity;

    private PlatformSnapshot(
        final int runtimeRelease,
        final List<ModuleIdentity> modules,
        final ClassPool jdkClassTable) {
      this.activeRuntimeFeature = runtimeRelease;
      this.modules = List.copyOf(modules);
      this.jdkClassTable = jdkClassTable;
      final StringBuilder value =
          new StringBuilder(128)
              .append("platform-source=jrt\nreader=")
              .append(READER_POLICY_VERSION)
              .append("\nruntime-release=")
              .append(runtimeRelease)
              .append('\n');
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

    /** Returns the active runtime feature release. */
    public int runtimeRelease() {
      return activeRuntimeFeature;
    }

    /** Returns the descriptive source kind for this active runtime platform. */
    public String sourceKind() {
      return "jrt";
    }

    /** Returns deterministic module-level identities for all system modules. */
    public List<ModuleIdentity> moduleIdentities() {
      return modules;
    }

    /** Returns the deterministic content identity used by the trim fingerprint. */
    public String identity() {
      return platformIdentity;
    }

    ClassPool classTableTemplate() {
      return jdkClassTable;
    }
  }
}
