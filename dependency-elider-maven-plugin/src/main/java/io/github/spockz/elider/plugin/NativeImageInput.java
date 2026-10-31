/* WHY: Gives schema readers one source-neutral way to open descriptors and sibling data. */

package io.github.spockz.elider.plugin;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

/** Represents an explicitly typed descriptor from an archive or file. */
final class NativeImageInput {
  /** WHY: Dispatch depends on the declared schema, never on the source filename. */
  private final NativeImageDescriptorKind descriptorKind;

  /** WHY: Diagnostics need the source's stable archive entry or absolute path. */
  private final String displayName;

  /** WHY: Both source forms must also resolve sibling bytes for predefined classes. */
  private final Source inputSource;

  private NativeImageInput(
      final NativeImageDescriptorKind kind, final String name, final Source source) {
    this.descriptorKind = java.util.Objects.requireNonNull(kind, "kind");
    this.displayName = java.util.Objects.requireNonNull(name, "name");
    this.inputSource = java.util.Objects.requireNonNull(source, "source");
  }

  /* package */
  static NativeImageInput archiveEntry(
      final JarFile archive, final String entryName, final NativeImageDescriptorKind kind)
      throws IOException {
    final JarEntry entry = archive.getJarEntry(entryName);
    if (entry == null || entry.isDirectory()) {
      throw new IOException("Native-image descriptor is missing: " + entryName);
    }
    return archiveEntry(archive, entry, kind);
  }

  /* package */
  static NativeImageInput archiveEntry(
      final JarFile archive, final JarEntry entry, final NativeImageDescriptorKind kind) {
    if (entry.isDirectory()) {
      throw new IllegalArgumentException("Native-image input cannot be a directory: " + entry);
    }
    return new NativeImageInput(kind, entry.getName(), new ArchiveSource(archive, entry));
  }

  /* package */
  static NativeImageInput file(final Path path, final NativeImageDescriptorKind kind) {
    final Path normalized = path.toAbsolutePath().normalize();
    return new NativeImageInput(kind, normalized.toString(), new FileSource(normalized, kind));
  }

  /* package */
  NativeImageDescriptorKind kind() {
    return descriptorKind;
  }

  /* package */
  String name() {
    return displayName;
  }

  /* package */ String selectionIdentity() {
    return inputSource.identity();
  }

  /* package */
  InputStream open() throws IOException {
    return inputSource.open();
  }

  /* package */
  void readDescriptor(
      final NativeImageScanContext.DescriptorReader reader,
      final String resourcePath,
      final Path provider)
      throws IOException {
    try {
      reader.read(this);
    } catch (final IOException exception) {
      throw new IOException(
          "Cannot parse native-image resource "
              + resourcePath
              + " from provider archive "
              + provider
              + ": "
              + exception.getMessage(),
          exception);
    }
  }

  /* package */
  InputStream openSibling(final String relativeName) throws IOException {
    return inputSource.openSibling(relativeName);
  }

  /* package */
  List<NativeImageConsumedInput> consumedInputs() {
    return inputSource.consumedInputs();
  }

  /** WHY: Archive and filesystem sources share descriptor-relative sibling semantics. */
  private interface Source {
    /** WHY: Reader code consumes streams so schema parsers remain source-neutral. */
    InputStream open() throws IOException;

    /** WHY: Keep each descriptor's include and exclude group distinct. */
    String identity();

    /** WHY: Predefined class bytes are resolved relative to their descriptor source. */
    InputStream openSibling(String relativeName) throws IOException;

    /** WHY: External source bytes join the cache identity; archive entries already do. */
    List<NativeImageConsumedInput> consumedInputs();
  }

  private record ArchiveSource(JarFile archive, JarEntry entry) implements Source {
    @Override
    public String identity() {
      return archive.getName() + "!/" + entry.getName();
    }

    @Override
    public InputStream open() throws IOException {
      return archive.getInputStream(entry);
    }

    @Override
    public InputStream openSibling(final String relativeName) throws IOException {
      final String entryName = entry.getName();
      final int slash = entryName.lastIndexOf('/');
      final String siblingName = entryName.substring(0, slash + 1) + relativeName;
      final JarEntry entry = archive.getJarEntry(siblingName);
      if (entry == null || entry.isDirectory()) {
        throw new IOException("Native-image sibling data is missing: " + siblingName);
      }
      return archive.getInputStream(entry);
    }

    @Override
    public List<NativeImageConsumedInput> consumedInputs() {
      return List.of();
    }
  }

  /** WHY: Parser and cache identity share each captured byte array. */
  private static final class FileSource implements Source {
    /** WHY: The path remains logical for descriptor-relative sibling lookup. */
    private final Path path;

    /** WHY: The declared kind distinguishes otherwise arbitrary external filenames. */
    private final NativeImageDescriptorKind kind;

    /** WHY: One descriptor's reads and sibling captures run sequentially during scan. */
    private final List<CapturedFile> capturedFiles = new java.util.ArrayList<>();

    private FileSource(final Path path, final NativeImageDescriptorKind kind) {
      this.path = path;
      this.kind = kind;
    }

    @Override
    public String identity() {
      return path.toString();
    }

    @Override
    public InputStream open() throws IOException {
      if (!Files.isRegularFile(path)) {
        throw new IOException("Native-image descriptor is missing: " + path);
      }
      return new ByteArrayInputStream(capture(path, "descriptor:" + kind).bytes());
    }

    @Override
    public InputStream openSibling(final String relativeName) throws IOException {
      final Path parent = path.getParent();
      if (parent == null) {
        throw new IOException("Native-image descriptor has no parent directory: " + path);
      }
      final Path sibling = parent.resolve(relativeName).normalize();
      if (!sibling.startsWith(parent)) {
        throw new IOException("Native-image sibling path escapes descriptor directory: " + path);
      }
      if (!Files.isRegularFile(sibling)) {
        throw new IOException("Native-image sibling data is missing: " + sibling);
      }
      final Path realParent = parent.toRealPath();
      final Path realSibling = sibling.toRealPath();
      if (!realSibling.startsWith(realParent)) {
        throw new IOException("Native-image sibling path escapes descriptor directory: " + path);
      }
      return new ByteArrayInputStream(capture(sibling, "predefined-classdata").bytes());
    }

    @Override
    public List<NativeImageConsumedInput> consumedInputs() {
      return capturedFiles.stream().map(CapturedFile::snapshot).toList();
    }

    private CapturedFile capture(final Path logicalPath, final String role) throws IOException {
      final Path normalized = logicalPath.toAbsolutePath().normalize();
      final String key = role + "|" + normalized;
      for (final CapturedFile existing : capturedFiles) {
        if (existing.identity().equals(key)) {
          return existing;
        }
      }
      final Path canonical = normalized.toRealPath();
      final byte[] bytes = Files.readAllBytes(canonical);
      if (!canonical.equals(normalized.toRealPath())) {
        throw new IOException("Native-image input target changed while being read: " + normalized);
      }
      final CapturedFile captured =
          new CapturedFile(
              key,
              bytes,
              new NativeImageConsumedInput(
                  normalized,
                  canonical,
                  role,
                  bytes.length,
                  NativeImageConsumedInput.digest(bytes)));
      capturedFiles.add(captured);
      return captured;
    }
  }

  private record CapturedFile(String identity, byte[] bytes, NativeImageConsumedInput snapshot) {}
}
