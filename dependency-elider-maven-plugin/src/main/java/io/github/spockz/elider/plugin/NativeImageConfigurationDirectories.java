/* WHY: Dispatches option values to distinct filesystem and classpath root resolvers. */

package io.github.spockz.elider.plugin;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Set;
import java.util.jar.JarEntry;

/** Dispatches the two bounded Native Image descriptor directory options. */
final class NativeImageConfigurationDirectories {
  private NativeImageConfigurationDirectories() {}

  /* package */ static boolean isOption(final String argument) {
    return "-H:ConfigurationFileDirectories".equals(argument)
        || argument.startsWith("-H:ConfigurationFileDirectories=")
        || "-H:ConfigurationResourceRoots".equals(argument)
        || argument.startsWith("-H:ConfigurationResourceRoots=");
  }

  /* package */ static boolean read(
      final String argument,
      final JarEntry propertiesEntry,
      final Set<String> roots,
      final NativeImageScanContext context,
      final Set<Path> resourceProviders,
      final Set<NativeImageConsumedInput> consumedInputs)
      throws IOException {
    if (argument.startsWith("-H:ConfigurationFileDirectories=")) {
      return NativeImageFileConfigurationDirectories.read(
          argument.substring("-H:ConfigurationFileDirectories=".length()),
          propertiesEntry,
          roots,
          context,
          consumedInputs);
    }
    if (argument.startsWith("-H:ConfigurationResourceRoots=")) {
      return NativeImageResourceConfigurationDirectories.read(
          argument.substring("-H:ConfigurationResourceRoots=".length()),
          propertiesEntry,
          roots,
          context,
          resourceProviders,
          consumedInputs);
    }
    throw new IOException(
        "Native-image configuration directory option has no value in "
            + propertiesEntry.getName()
            + ": "
            + argument);
  }
}
