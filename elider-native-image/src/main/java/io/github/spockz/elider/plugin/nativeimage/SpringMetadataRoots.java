/* WHY: Keeps Spring metadata validation separate from archive and native-image dispatch. */

package io.github.spockz.elider.plugin.nativeimage;

import io.github.spockz.elider.model.AsciiBinaryClassName;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Properties;
import java.util.Set;

/** Parses supported Spring class-name metadata into conservative roots. */
final class SpringMetadataRoots {
  private SpringMetadataRoots() {
    throw new AssertionError("No instances");
  }

  /* package */ static boolean readFactories(final InputStream input, final Set<String> roots)
      throws IOException {
    final Properties factories = new Properties();
    try (InputStream stream = input) {
      factories.load(stream);
    }
    for (final String key : factories.stringPropertyNames()) {
      final String factory = key.trim();
      if (!AsciiBinaryClassName.isValid(factory)) {
        throw new IOException("Malformed Spring factory interface name: " + key);
      }
      roots.add(factory);
      for (final String provider : factories.getProperty(key).split(",")) {
        final String className = provider.trim();
        if (!AsciiBinaryClassName.isValid(className)) {
          throw new IOException("Malformed Spring factory implementation: " + provider);
        }
        roots.add(className);
      }
    }
    return true;
  }

  /* package */ static void readImports(
      final InputStream input, final Set<String> roots, final String entryName) throws IOException {
    try (BufferedReader reader =
        new BufferedReader(new InputStreamReader(input, StandardCharsets.UTF_8))) {
      String line = reader.readLine();
      while (line != null) {
        final String className = line.split("#", 2)[0].trim();
        if (!className.isEmpty()) {
          if (!AsciiBinaryClassName.isValid(className)) {
            throw new IOException("Malformed Spring AutoConfiguration import in " + entryName);
          }
          roots.add(className);
        }
        line = reader.readLine();
      }
    }
  }
}
