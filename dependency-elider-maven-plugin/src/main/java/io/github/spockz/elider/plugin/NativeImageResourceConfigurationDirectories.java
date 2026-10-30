/* WHY: Resolves every descriptor below an exact classpath resource-root boundary. */

package io.github.spockz.elider.plugin;

import java.io.IOException;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.Set;
import java.util.jar.JarEntry;

/** Reads recognized descriptors discovered under classpath resource roots. */
/* package */ final class NativeImageResourceConfigurationDirectories {
  private NativeImageResourceConfigurationDirectories() {}

  /* package */ static boolean read(
      final String values,
      final JarEntry propertiesEntry,
      final Set<String> roots,
      final NativeImageScanContext context,
      final Set<Path> resourceProviders,
      final Set<NativeImageConsumedInput> consumedInputs)
      throws IOException {
    boolean foundRoots = false;
    final Set<String> processedResources = new HashSet<>();
    for (final String root :
        NativeImageConfigurationDirectorySupport.references(values, propertiesEntry)) {
      for (final String resource :
          NativeImageResourceRootIndex.descriptorsUnder(
              context.resourceIndex(), root, propertiesEntry)) {
        if (processedResources.add(resource)) {
          foundRoots |=
              readResource(
                  resource, propertiesEntry, roots, context, resourceProviders, consumedInputs);
        }
      }
    }
    return foundRoots;
  }

  private static boolean readResource(
      final String resource,
      final JarEntry propertiesEntry,
      final Set<String> roots,
      final NativeImageScanContext context,
      final Set<Path> resourceProviders,
      final Set<NativeImageConsumedInput> consumedInputs)
      throws IOException {
    final NativeImageDescriptorKind kind =
        NativeImageConfigurationDirectorySupport.kindFor(resource);
    final int priorRoots = roots.size();
    if (!context.readClasspathResource(
        resource,
        kind,
        input ->
            NativeImageConfigurationPointers.readTypedDescriptor(
                input, kind, roots, consumedInputs),
        resourceProviders)) {
      throw new IOException(
          "Native-image configuration resource is missing in "
              + propertiesEntry.getName()
              + ": "
              + resource);
    }
    return roots.size() > priorRoots;
  }
}
