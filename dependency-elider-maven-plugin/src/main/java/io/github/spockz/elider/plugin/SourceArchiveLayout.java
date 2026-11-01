// WHY: Rejects archive metadata and paths outside the supported ordinary-JAR layout.

package io.github.spockz.elider.plugin;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Map;
import java.util.Optional;
import java.util.jar.Attributes;
import java.util.jar.JarFile;
import java.util.jar.Manifest;

/** Enforces supported source archive structure. */
final class SourceArchiveLayout {
  /** Physical prefix used to reject versioned class trees. */
  private static final String VERSIONED_ENTRIES = "META-INF/versions/";

  private SourceArchiveLayout() {}

  /* default */ static void requireSupportedManifest(final JarFile jar, final Path path)
      throws IOException {
    final Manifest manifest = readManifest(jar);
    if (manifest == null) {
      return;
    }
    final Optional<String> multiRelease = mainAttribute(manifest, Attributes.Name.MULTI_RELEASE);
    if (multiRelease.map(String::trim).map(Boolean::parseBoolean).orElse(false)) {
      throw new IOException("Multi-release archives are unsupported: " + path);
    }
    final Optional<String> classPath = mainAttribute(manifest, Attributes.Name.CLASS_PATH);
    if (classPath.filter(value -> !value.isBlank()).isPresent()) {
      throw new IOException("Manifest Class-Path is unsupported: " + path);
    }
  }

  private static Manifest readManifest(final JarFile jar) throws IOException {
    return jar.getManifest();
  }

  private static Optional<String> mainAttribute(
      final Manifest manifest, final Attributes.Name name) {
    final Map<Object, Object> attributes = manifest.getMainAttributes();
    final Object value = attributes.get(name);
    return value instanceof String text ? Optional.of(text) : Optional.empty();
  }

  /* default */ static void requireNonVersioned(final String name) throws IOException {
    if (name.startsWith(VERSIONED_ENTRIES)) {
      throw new IOException("Multi-release archive entry is unsupported: " + name);
    }
  }

  /* default */ static void requireSafePath(final String name, final Path archive)
      throws IOException {
    if (isUnsafePath(name)) {
      throw new IOException("Unsafe archive entry path in " + archive + ": " + name);
    }
  }

  private static boolean isUnsafePath(final String name) {
    return name.isBlank()
        || name.startsWith("/")
        || name.indexOf('\\') >= 0
        || Arrays.stream(name.split("/", -1))
            .anyMatch(segment -> segment.isBlank() || ".".equals(segment) || "..".equals(segment));
  }
}
