/* WHY: Gives JPMS resolution and indexing the selected runtime module descriptors and bytes. */

package io.github.spockz.elider.trimmer;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.module.ModuleDescriptor;
import java.lang.module.ModuleFinder;
import java.lang.module.ModuleReader;
import java.lang.module.ModuleReference;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Stream;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;

@SuppressWarnings({
  "PMD.CommentRequired",
  "PMD.CommentDefaultAccessModifier",
  "PMD.UseConcurrentHashMap"
})
final class RuntimeModuleFinder implements ModuleFinder {
  private static final String MODULE_INFO = "module-info.class";

  private final Map<String, ModuleReference> modules;

  private RuntimeModuleFinder(final Map<String, ModuleReference> modules) {
    this.modules = Map.copyOf(modules);
  }

  @SuppressWarnings("PMD.AvoidInstantiatingObjectsInLoops")
  static RuntimeModuleFinder read(final Path root) throws IOException {
    final List<Path> paths;
    try (Stream<Path> entries = Files.list(root)) {
      paths = entries.sorted().toList();
    }
    final Map<String, ModuleReference> modules = new HashMap<>();
    for (final Path path : paths) {
      final byte[] bytes = Files.readAllBytes(path.resolve(MODULE_INFO));
      final ModuleDescriptor descriptor = readDescriptor(bytes);
      if (!root.relativize(path).toString().equals(descriptor.name())) {
        throw new IOException("Runtime module directory disagrees with its descriptor: " + path);
      }
      modules.put(descriptor.name(), new ImageModule(descriptor, path, bytes));
    }
    if (!modules.containsKey("java.base")) {
      throw new IOException("Runtime image has no java.base module");
    }
    return new RuntimeModuleFinder(modules);
  }

  static ModuleFinder descriptors(final List<ModuleDescriptor> descriptors) {
    return new RuntimeModuleFinder(
        descriptors.stream()
            .collect(
                java.util.stream.Collectors.toUnmodifiableMap(
                    ModuleDescriptor::name, DescriptorReference::new)));
  }

  void validateVersion(final Runtime.Version expected) throws IOException {
    final Optional<String> version = modules.get("java.base").descriptor().rawVersion();
    if (version.isPresent()
        && !expected.version().equals(Runtime.Version.parse(version.get()).version())) {
      throw new IOException(
          "Release metadata disagrees with java.base module version " + version.get());
    }
  }

  /* package */ static ModuleDescriptor readDescriptor(final byte[] bytes) {
    final ClassReader source = new ClassReader(bytes);
    if (source.readUnsignedShort(6) <= Runtime.version().feature() + 44) {
      return ModuleDescriptor.read(ByteBuffer.wrap(bytes));
    }
    final ClassWriter writer = new ClassWriter(source, 0);
    source.accept(
        new ClassVisitor(Opcodes.ASM9, writer) {
          @Override
          public void visit(
              final int version,
              final int access,
              final String name,
              final String signature,
              final String superName,
              final String[] interfaces) {
            super.visit(Opcodes.V9, access, name, signature, superName, interfaces);
          }
        },
        0);
    return ModuleDescriptor.read(ByteBuffer.wrap(writer.toByteArray()));
  }

  @Override
  public Optional<ModuleReference> find(final String name) {
    return Optional.ofNullable(modules.get(name));
  }

  @Override
  public Set<ModuleReference> findAll() {
    return Set.copyOf(modules.values());
  }

  private static final class ImageModule extends ModuleReference {
    private final Path path;
    private final byte[] descriptorBytes;

    private ImageModule(
        final ModuleDescriptor descriptor, final Path path, final byte[] descriptorBytes) {
      super(descriptor, URI.create("jrt:/" + descriptor.name()));
      this.path = path;
      this.descriptorBytes = descriptorBytes;
    }

    @Override
    public ModuleReader open() {
      return new ImageModuleReader(path, descriptorBytes);
    }
  }

  private static final class DescriptorReference extends ModuleReference {
    private DescriptorReference(final ModuleDescriptor descriptor) {
      super(descriptor, null);
    }

    @Override
    public ModuleReader open() throws IOException {
      throw new IOException("This module reference is for descriptor resolution only");
    }
  }

  private record ImageModuleReader(Path root, byte[] descriptorBytes) implements ModuleReader {
    @Override
    public Optional<URI> find(final String name) {
      final Path file = root.resolve(name);
      return Files.isRegularFile(file) ? Optional.of(file.toUri()) : Optional.empty();
    }

    @Override
    public Optional<InputStream> open(final String name) throws IOException {
      if (MODULE_INFO.equals(name)) {
        return Optional.of(new ByteArrayInputStream(descriptorBytes));
      }
      final Path file = root.resolve(name);
      return Files.isRegularFile(file) ? Optional.of(Files.newInputStream(file)) : Optional.empty();
    }

    @Override
    public Stream<String> list() throws IOException {
      return Files.walk(root)
          .filter(Files::isRegularFile)
          .map(root::relativize)
          .map(Path::toString);
    }

    @Override
    public void close() {
      // The enclosing image owns the file system.
    }
  }
}
