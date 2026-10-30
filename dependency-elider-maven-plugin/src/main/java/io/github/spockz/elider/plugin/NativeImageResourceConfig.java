/* WHY: Validates native-image resource and bundle configuration. */

package io.github.spockz.elider.plugin;

import java.io.IOException;
import java.util.Set;
import java.util.jar.JarFile;

/** Validates supported native-image metadata. */
final class NativeImageResourceConfig {
  private NativeImageResourceConfig() {}

  /* package */
  static boolean isNativeImageResourceConfig(final String name) {
    return name.endsWith("resource-config.json") || name.endsWith("-resource.json");
  }

  /* package */
  static void readNativeImageResourceConfig(
      final JarFile archive, final String name, final Set<String> roots) throws IOException {
    readNativeImageResourceConfig(
        NativeImageInput.archiveEntry(archive, name, NativeImageDescriptorKind.RESOURCES), roots);
  }

  /* package */
  static void readNativeImageResourceConfig(final NativeImageInput input, final Set<String> roots)
      throws IOException {
    readNativeImageResourceConfig(input, roots, null);
  }

  /* package */
  static void readNativeImageResourceConfig(
      final NativeImageInput input,
      final Set<String> roots,
      final Set<NativeImageConsumedInput> consumedInputs)
      throws IOException {
    readNativeImageResourceConfig(input, roots, consumedInputs, null);
  }

  /* package */ static void readNativeImageResourceConfig(
      final NativeImageInput input,
      final Set<String> roots,
      final Set<NativeImageConsumedInput> consumedInputs,
      final NativeImagePolicyRoots.ResourcePatterns selections)
      throws IOException {
    if (input.kind() != NativeImageDescriptorKind.RESOURCES) {
      throw new IOException("Unsupported native-image resource descriptor kind: " + input.name());
    }
    NativeImageResourceDocument.read(input, roots, selections);
    if (consumedInputs != null) {
      consumedInputs.addAll(input.consumedInputs());
    }
  }
}
