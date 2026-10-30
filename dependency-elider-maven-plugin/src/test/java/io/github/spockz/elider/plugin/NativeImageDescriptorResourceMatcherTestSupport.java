/* WHY: Shares classpath and filesystem fixtures for resource matcher acceptance tests. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactFileRef;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;

/** Builds archive fixtures and applies deferred selectors to their full index. */
/* package */ final class NativeImageDescriptorResourceMatcherTestSupport {
  private NativeImageDescriptorResourceMatcherTestSupport() {
    throw new AssertionError("static descriptor matcher test support");
  }

  /* package */ static Path propertiesArchive(
      final Path directory, final String name, final String arguments) throws IOException {
    return NativeImageScanContextTestSupport.jar(
        directory,
        name,
        NativeImageScanContextTestSupport.PROPERTIES_ENTRY,
        "Args = " + (arguments.isEmpty() ? "-H:-UseServiceLoaderFeature" : arguments));
  }

  /* package */ static Path propertiesArchive(
      final Path directory,
      final String name,
      final String arguments,
      final String descriptor,
      final String content)
      throws IOException {
    return NativeImageScanContextTestSupport.jar(
        directory,
        name,
        NativeImageScanContextTestSupport.PROPERTIES_ENTRY,
        "Args = " + (arguments.isEmpty() ? "-H:-UseServiceLoaderFeature" : arguments),
        descriptor,
        content);
  }

  /* package */ static Path archive(
      final Path directory, final String name, final String... entries) throws IOException {
    return NativeImageScanContextTestSupport.jar(directory, name, entries);
  }

  /* package */ static Path resourceConfigArchive(
      final Path directory, final String name, final String document) throws IOException {
    return propertiesArchive(
        directory, name, "", "META-INF/native-image/test/resource-config.json", document);
  }

  /* package */ static Path classArchive(
      final Path directory, final String name, final String classEntry) throws IOException {
    return archiveWithClasses(directory, name, Map.of(), classEntry);
  }

  /* package */ static Path archiveWithClasses(
      final Path directory,
      final String name,
      final Map<String, String> resources,
      final String... classEntries)
      throws IOException {
    final Path path = directory.resolve(name);
    try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(path))) {
      for (final Map.Entry<String, String> resource : resources.entrySet()) {
        writeEntry(
            output,
            resource.getKey(),
            resource.getValue().getBytes(java.nio.charset.StandardCharsets.UTF_8));
      }
      final byte[] content = classBytes();
      for (final String classEntry : classEntries) {
        writeEntry(output, classEntry, content);
      }
    }
    return path;
  }

  /* package */ static ObservedRoots scan(
      final Path invocationBase, final Path declaring, final Path... providers) throws IOException {
    final List<ArtifactFileRef> candidates = new ArrayList<>();
    candidates.add(NativeImageScanContextTestSupport.candidate("declaring", declaring));
    for (int index = 0; index < providers.length; index++) {
      candidates.add(
          NativeImageScanContextTestSupport.candidate("provider-" + index, providers[index]));
    }
    final NativeImageScanContext context =
        NativeImageScanContext.create(candidates, invocationBase);
    final DependencyDynamicRoots.RootScan scan =
        DependencyDynamicRoots.scan(declaring, context, Set.of(), true);
    final Set<String> roots = new HashSet<>(scan.roots());
    final Set<Path> resourceProviders = new HashSet<>(scan.resourceProviders());
    NativeImagePolicyRoots.applyResourcePatterns(
        List.of(scan.resourcePatterns()), context, roots, resourceProviders);
    return new ObservedRoots(Set.copyOf(roots), Set.copyOf(resourceProviders));
  }

  /* package */ static String patternDocument(final String pattern) {
    return "{\"resources\":{\"includes\":[{\"pattern\":\"" + pattern + "\"}]}}";
  }

  private static byte[] classBytes() throws IOException {
    try (InputStream input =
        NativeImageDescriptorResourceMatcherTestSupport.class.getResourceAsStream(
            "NativeImageDescriptorResourceMatcherTestSupport.class")) {
      if (input == null) {
        throw new IOException("Cannot read test class bytes");
      }
      return input.readAllBytes();
    }
  }

  private static void writeEntry(
      final JarOutputStream output, final String name, final byte[] content) throws IOException {
    output.putNextEntry(new JarEntry(name));
    output.write(content);
    output.closeEntry();
  }

  /* package */ record ObservedRoots(Set<String> roots, Set<Path> providers) {}
}
