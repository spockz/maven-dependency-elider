/* WHY: Keeps descriptor option types explicit across classpath and filesystem sources. */

package io.github.spockz.elider.plugin;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

/** Resolves GraalVM pointer options by their audited schema. */
final class NativeImageConfigurationPointers {
  /** WHY: A source filename cannot select a descriptor schema. */
  private static final List<Pointer> POINTERS =
      List.of(
          new Pointer(
              "-H:ReflectionConfigurationResources",
              NativeImageDescriptorKind.REFLECTION,
              true,
              true),
          new Pointer(
              "-H:JNIConfigurationResources", NativeImageDescriptorKind.REFLECTION, true, true),
          new Pointer(
              "-H:DynamicProxyConfigurationResources", NativeImageDescriptorKind.PROXY, true, true),
          new Pointer(
              "-H:SerializationConfigurationResources",
              NativeImageDescriptorKind.SERIALIZATION,
              true,
              true),
          new Pointer(
              "-H:SerializationDenyConfigurationResources",
              NativeImageDescriptorKind.SERIALIZATION_DENY,
              true,
              false),
          new Pointer(
              "-H:PredefinedClassesConfigurationResources",
              NativeImageDescriptorKind.PREDEFINED_CLASSES,
              true,
              true),
          new Pointer(
              "-H:ResourceConfigurationResources",
              NativeImageDescriptorKind.RESOURCES,
              true,
              false),
          new Pointer("-H:ForeignResources", NativeImageDescriptorKind.FOREIGN, true, false),
          new Pointer(
              "-H:ObjectInliningConfigurationResources",
              NativeImageDescriptorKind.OBJECT_INLINING,
              true,
              true),
          new Pointer(
              "-H:ReachabilityMetadataResources",
              NativeImageDescriptorKind.REACHABILITY_METADATA,
              true,
              true),
          new Pointer(
              "-H:ReflectionConfigurationFiles", NativeImageDescriptorKind.REFLECTION, false, true),
          new Pointer(
              "-H:JNIConfigurationFiles", NativeImageDescriptorKind.REFLECTION, false, true),
          new Pointer(
              "-H:DynamicProxyConfigurationFiles", NativeImageDescriptorKind.PROXY, false, true),
          new Pointer(
              "-H:SerializationConfigurationFiles",
              NativeImageDescriptorKind.SERIALIZATION,
              false,
              true),
          new Pointer(
              "-H:SerializationDenyConfigurationFiles",
              NativeImageDescriptorKind.SERIALIZATION_DENY,
              false,
              false),
          new Pointer(
              "-H:PredefinedClassesConfigurationFiles",
              NativeImageDescriptorKind.PREDEFINED_CLASSES,
              false,
              true),
          new Pointer(
              "-H:ResourceConfigurationFiles", NativeImageDescriptorKind.RESOURCES, false, false),
          new Pointer(
              "-H:ForeignConfigurationFiles", NativeImageDescriptorKind.FOREIGN, false, false),
          new Pointer(
              "-H:ObjectInliningConfigurationFiles",
              NativeImageDescriptorKind.OBJECT_INLINING,
              false,
              true));

  private NativeImageConfigurationPointers() {}

  /* package */
  static boolean isPointer(final String argument) {
    return NativeImageConfigurationDirectories.isOption(argument)
        || POINTERS.stream()
            .anyMatch(
                pointer ->
                    argument.equals(pointer.option())
                        || argument.startsWith(pointer.option() + "="));
  }

  /* package */
  static Optional<Boolean> read(
      final String argument,
      final JarFile archive,
      final JarEntry propertiesEntry,
      final Set<String> roots,
      final NativeImageScanContext scanContext,
      final Set<Path> resourceProviders,
      final Set<NativeImageConsumedInput> consumedInputs)
      throws IOException {
    if (NativeImageConfigurationDirectories.isOption(argument)) {
      return Optional.of(
          NativeImageConfigurationDirectories.read(
              argument, propertiesEntry, roots, scanContext, resourceProviders, consumedInputs));
    }
    for (final Pointer pointer : POINTERS) {
      if (argument.equals(pointer.option())) {
        throw missingValue(argument, propertiesEntry);
      }
      final String valuePrefix = pointer.option() + "=";
      if (argument.startsWith(valuePrefix)) {
        final String values = argument.substring(valuePrefix.length());
        if (pointer.resource()) {
          readResources(
              values,
              pointer,
              archive,
              propertiesEntry,
              roots,
              scanContext,
              resourceProviders,
              consumedInputs);
        } else {
          readFiles(values, pointer, propertiesEntry, roots, scanContext, consumedInputs);
        }
        return Optional.of(pointer.declaresClassRoots());
      }
    }
    return Optional.empty();
  }

  private static void readResources(
      final String values,
      final Pointer pointer,
      final JarFile archive,
      final JarEntry propertiesEntry,
      final Set<String> roots,
      final NativeImageScanContext scanContext,
      final Set<Path> resourceProviders,
      final Set<NativeImageConsumedInput> consumedInputs)
      throws IOException {
    for (final String reference : references(values, propertiesEntry)) {
      final boolean descriptorRelative = reference.startsWith("${.}/");
      final String resource =
          NativeImageDynamicRoots.resolveNativeImageConfigPath(
              propertiesEntry.getName(), reference, descriptorRelative);
      final NativeImageScanContext.DescriptorReader reader =
          input -> readTypedDescriptor(input, pointer.kind(), roots, consumedInputs);
      final boolean found;
      try {
        found =
            descriptorRelative
                ? scanContext.readDescriptorRelativeResource(
                    archive, resource, pointer.kind(), reader, resourceProviders)
                : scanContext.readClasspathResource(
                    resource, pointer.kind(), reader, resourceProviders);
      } catch (final IOException exception) {
        throw new IOException(
            "Cannot read native-image configuration resource "
                + resource
                + ": "
                + exception.getMessage(),
            exception);
      }
      if (!found) {
        throw new IOException("Native-image configuration resource is missing: " + resource);
      }
    }
  }

  private static void readFiles(
      final String values,
      final Pointer pointer,
      final JarEntry propertiesEntry,
      final Set<String> roots,
      final NativeImageScanContext scanContext,
      final Set<NativeImageConsumedInput> consumedInputs)
      throws IOException {
    final Path invocationBase =
        scanContext
            .invocationBaseDirectory()
            .orElseThrow(
                () ->
                    new IOException(
                        "Native-image configuration files require an invocation base: "
                            + propertiesEntry.getName()));
    for (final String reference : references(values, propertiesEntry)) {
      final Path logicalPath = resolveFilePath(reference, invocationBase, propertiesEntry);
      final NativeImageInput input = NativeImageInput.file(logicalPath, pointer.kind());
      readTypedDescriptor(input, pointer.kind(), roots, consumedInputs);
    }
  }

  private static Path resolveFilePath(
      final String reference, final Path invocationBase, final JarEntry propertiesEntry)
      throws IOException {
    final Path requested;
    try {
      requested = Path.of(reference);
    } catch (final java.nio.file.InvalidPathException exception) {
      throw new IOException(
          "Invalid native-image configuration file path in "
              + propertiesEntry.getName()
              + ": "
              + reference,
          exception);
    }
    if (requested.isAbsolute()) {
      return requested.normalize();
    }
    final Path logicalPath = invocationBase.resolve(requested).normalize();
    if (!logicalPath.startsWith(invocationBase)) {
      throw new IOException(
          "Native-image configuration file escapes invocation base: " + reference);
    }
    final Path canonicalBase = canonicalPath(invocationBase, propertiesEntry);
    final Path canonicalFile = canonicalPath(logicalPath, propertiesEntry);
    if (!canonicalFile.startsWith(canonicalBase)) {
      throw new IOException(
          "Native-image configuration file escapes invocation base: " + reference);
    }
    return logicalPath;
  }

  private static Path canonicalPath(final Path path, final JarEntry propertiesEntry)
      throws IOException {
    try {
      return path.toRealPath();
    } catch (final IOException exception) {
      throw new IOException(
          "Cannot resolve native-image configuration path referenced by "
              + propertiesEntry.getName()
              + ": "
              + path,
          exception);
    }
  }

  /* package */ static void readTypedDescriptor(
      final NativeImageInput input,
      final NativeImageDescriptorKind kind,
      final Set<String> roots,
      final Set<NativeImageConsumedInput> consumedInputs)
      throws IOException {
    if (input.kind() != kind) {
      throw new IOException("Native-image descriptor kind mismatch: " + input.name());
    }
    if (kind == NativeImageDescriptorKind.RESOURCES) {
      NativeImageResourceConfig.readNativeImageResourceConfig(input, roots, consumedInputs);
    } else {
      NativeImageClassConfig.readNativeImageClassConfig(input, roots, consumedInputs);
    }
  }

  private static List<String> references(final String values, final JarEntry propertiesEntry)
      throws IOException {
    if (values.isBlank()) {
      throw new IOException(
          "Native-image configuration pointer has no paths in " + propertiesEntry.getName());
    }
    final List<String> references =
        java.util.Arrays.stream(values.split(",", -1)).map(String::trim).toList();
    if (references.stream().anyMatch(String::isBlank)) {
      throw new IOException(
          "Native-image configuration pointer has an empty path in " + propertiesEntry.getName());
    }
    return references;
  }

  private static IOException missingValue(final String argument, final JarEntry propertiesEntry) {
    return new IOException(
        "Native-image configuration pointer has no value in "
            + propertiesEntry.getName()
            + ": "
            + argument);
  }

  private record Pointer(
      String option,
      NativeImageDescriptorKind kind,
      boolean resource,
      boolean declaresClassRoots) {}
}
