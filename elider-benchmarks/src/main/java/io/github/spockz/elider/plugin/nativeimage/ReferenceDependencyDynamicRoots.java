/* WHY: Preserves the former JarFile scanner as the baseline for differential tests and JMH. */

package io.github.spockz.elider.plugin.nativeimage;

import io.github.spockz.elider.model.AsciiBinaryClassName;
import io.github.spockz.elider.plugin.nativeimage.DependencyDynamicRoots.RootScan;
import io.github.spockz.elider.plugin.nativeimage.DependencyDynamicRoots.ServiceDescriptor;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

/** Reads dependency-local service provider and supported Graal native-image roots. */
@SuppressWarnings({"PMD.CommentRequired", "PMD.CyclomaticComplexity", "PMD.AssignmentInOperand"})
final class ReferenceDependencyDynamicRoots {
  private static final String SERVICES = "META-INF/services/";
  private static final String SPRING_FACTORIES = "META-INF/spring.factories";
  private static final String SPRING_IMPORTS =
      "META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports";

  private ReferenceDependencyDynamicRoots() {}

  /** Scans a single dependency JAR for dynamic loading metadata. */
  /* package */ static RootScan scan(final java.nio.file.Path jar) throws IOException {
    return scan(jar, NativeImageScanContext.singleArchive(jar));
  }

  /** Scans a dependency JAR using an existing native-image scan context. */
  /* package */ static RootScan scan(
      final java.nio.file.Path jar, final NativeImageScanContext scanContext) throws IOException {
    final ScanState state = new ScanState(scanContext);
    try (JarFile archive = new JarFile(jar.toFile())) {
      for (final JarEntry entry : archive.stream().toList()) {
        state.scanEntry(archive, entry);
      }
    }
    return state.finish();
  }

  /** Accumulates one archive's metadata while keeping entry dispatch small. */
  private static final class ScanState {
    /** Service and non-service roots combined for the final result. */
    private final Set<String> roots = new LinkedHashSet<>();

    /** Class roots declared by metadata that does not need service proof. */
    private final Set<String> nonServiceRoots = new LinkedHashSet<>();

    /** Service descriptors retained until reachability proof is applied. */
    private final Set<ServiceDescriptor> serviceDescriptors = new LinkedHashSet<>();

    /** Archives that supplied classpath configuration resources. */
    private final Set<java.nio.file.Path> resourceProviders = new LinkedHashSet<>();

    /** Resource patterns deferred until all invocation properties are scanned. */
    private final NativeImagePolicyRoots.ResourcePatterns resourcePatterns =
        new NativeImagePolicyRoots.ResourcePatterns();

    /** ServiceLoader options are deferred until candidates are aggregated. */
    private final NativeImageServiceLoaderPolicy.Builder serviceLoaderPolicy =
        new NativeImageServiceLoaderPolicy.Builder();

    /** External descriptor and predefined sibling bytes consumed by this archive scan. */
    private final Set<NativeImageConsumedInput> consumedInputs = new LinkedHashSet<>();

    /** Complete candidate inventory used by resource and package resolution. */
    private final NativeImageScanContext scanContext;

    /** Whether this archive declares class roots. */
    private boolean declaresClassRoots;

    /** Whether resource metadata must survive class trimming. */
    private boolean requiresArtifactRetention;

    /** Creates mutable state for one archive using the invocation resource index. */
    private ScanState(final NativeImageScanContext scanContext) {
      this.scanContext = scanContext;
    }

    /** Dispatches one archive entry to its supported dynamic-root reader. */
    private void scanEntry(final JarFile archive, final JarEntry entry) throws IOException {
      if (entry.isDirectory()) {
        return;
      }
      final String name = entry.getName();
      if (name.startsWith(SERVICES)) {
        declaresClassRoots = true;
        readServiceDescriptor(archive, entry);
      } else if (name.startsWith(NativeImageDynamicRoots.PREFIX)
          && NativeImageDynamicRoots.isNativeImageClassConfig(name)) {
        declaresClassRoots = true;
        requiresArtifactRetention |=
            NativeImageClassConfig.readNativeImageClassConfig(
                NativeImageInput.archiveEntry(
                    archive, name, NativeImageDescriptorKind.classConfigFor(name)),
                nonServiceRoots,
                null,
                resourcePatterns);
      } else if (name.startsWith(NativeImageDynamicRoots.PREFIX)
          && NativeImageDynamicRoots.isNativeImageResourceConfig(name)) {
        requiresArtifactRetention = true;
        NativeImageResourceConfig.readNativeImageResourceConfig(
            NativeImageInput.archiveEntry(archive, name, NativeImageDescriptorKind.RESOURCES),
            nonServiceRoots,
            null,
            resourcePatterns);
      } else if (name.startsWith(NativeImageDynamicRoots.PREFIX) && name.endsWith(".properties")) {
        readNativeImageProperties(archive, entry);
      } else if (name.startsWith(NativeImageDynamicRoots.PREFIX)
          && !NativeImageDynamicRoots.isNativeImageSbom(name)
          && name.endsWith(".json")) {
        throw new IOException("Unsupported native-image class metadata: " + name);
      } else if (SPRING_FACTORIES.equals(name)) {
        declaresClassRoots |=
            SpringMetadataRoots.readFactories(archive.getInputStream(entry), nonServiceRoots);
      } else if (SPRING_IMPORTS.equals(name)) {
        declaresClassRoots = true;
        SpringMetadataRoots.readImports(archive.getInputStream(entry), nonServiceRoots, name);
      }
    }

    private void readServiceDescriptor(final JarFile archive, final JarEntry entry)
        throws IOException {
      final String name = entry.getName();
      final String service = name.substring(SERVICES.length());
      if (service.isBlank() || service.contains("/")) {
        throw new IOException("Unsupported service descriptor path: " + name);
      }
      final Set<String> providers = new LinkedHashSet<>();
      try (BufferedReader reader =
          new BufferedReader(
              new InputStreamReader(archive.getInputStream(entry), StandardCharsets.UTF_8))) {
        String line;
        while ((line = reader.readLine()) != null) {
          final String provider = line.split("#", 2)[0].trim();
          if (!provider.isEmpty()) {
            if (!AsciiBinaryClassName.isValid(provider)) {
              throw new IOException("Malformed service provider in " + name + ": " + provider);
            }
            providers.add(provider);
          }
        }
      }
      serviceDescriptors.add(new ServiceDescriptor(service, providers));
      roots.add(service);
      roots.addAll(providers);
    }

    private void readNativeImageProperties(final JarFile archive, final JarEntry entry)
        throws IOException {
      final NativeImageDynamicRoots.PropertiesResult result =
          NativeImageDynamicRoots.readNativeImagePropertiesDetailed(
              archive, entry, nonServiceRoots, scanContext, resourceProviders, consumedInputs);
      declaresClassRoots |= result.declaresClassRoots();
      requiresArtifactRetention |= result.requiresArtifactRetention();
      resourcePatterns.merge(result.resourcePatterns());
      serviceLoaderPolicy.merge(result.serviceLoaderPolicy());
    }

    /** Freezes accumulated metadata into the result consumed by Maven pruning. */
    private RootScan finish() {
      roots.addAll(nonServiceRoots);
      return new RootScan(
          roots,
          declaresClassRoots,
          requiresArtifactRetention,
          serviceDescriptors,
          nonServiceRoots,
          resourceProviders,
          consumedInputs,
          resourcePatterns.snapshot(),
          serviceLoaderPolicy.snapshot());
    }
  }
}
