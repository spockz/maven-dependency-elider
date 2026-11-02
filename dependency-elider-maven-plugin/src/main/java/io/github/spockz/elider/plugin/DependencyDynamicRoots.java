/* WHY: Finds class names declared by dependency-local dynamic loading
 * metadata before a JAR is trimmed, since ordinary bytecode references
 * cannot describe SPI or native-image lookups. */

package io.github.spockz.elider.plugin;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Enumeration;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

/** Reads dependency-local service provider and supported Graal native-image roots. */
@SuppressWarnings({
  "PMD.CommentRequired",
  "PMD.CommentDefaultAccessModifier",
  "PMD.CyclomaticComplexity",
  "PMD.AssignmentInOperand"
})
final class DependencyDynamicRoots {
  private static final String SERVICES = "META-INF/services/";
  private static final String SPRING_FACTORIES = "META-INF/spring.factories";
  private static final String SPRING_IMPORTS =
      "META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports";
  private static final String SPRING_METADATA = "META-INF/spring-autoconfigure-metadata.properties";

  record ServiceDescriptor(String serviceInterface, Set<String> providers) {
    ServiceDescriptor {
      serviceInterface = java.util.Objects.requireNonNull(serviceInterface, "serviceInterface");
      providers = Set.copyOf(providers);
    }
  }

  record EffectiveRoots(
      Set<String> roots,
      Set<ServiceDescriptor> unprovenConservativeServices,
      Set<String> unprovenConservativeRoots,
      Set<String> featureRoots) {
    EffectiveRoots {
      roots = Set.copyOf(roots);
      unprovenConservativeServices = Set.copyOf(unprovenConservativeServices);
      unprovenConservativeRoots = Set.copyOf(unprovenConservativeRoots);
      featureRoots = Set.copyOf(featureRoots);
    }

    boolean declaresRoots() {
      return !roots.isEmpty();
    }
  }

  record RootScan(
      Set<String> roots,
      boolean declaresClassRoots,
      boolean requiresArtifactRetention,
      Set<ServiceDescriptor> serviceDescriptors,
      Set<String> nonServiceRoots,
      Set<java.nio.file.Path> resourceProviders,
      Set<NativeImageConsumedInput> consumedInputs,
      NativeImagePolicyRoots.ResourcePatternSelection resourcePatterns,
      NativeImageServiceLoaderPolicy.Selection serviceLoaderPolicy) {
    RootScan {
      roots = Set.copyOf(roots);
      serviceDescriptors = Set.copyOf(serviceDescriptors);
      nonServiceRoots = Set.copyOf(nonServiceRoots);
      resourceProviders = Set.copyOf(resourceProviders);
      consumedInputs = Set.copyOf(consumedInputs);
      resourcePatterns =
          resourcePatterns == null
              ? NativeImagePolicyRoots.ResourcePatternSelection.empty()
              : resourcePatterns;
      serviceLoaderPolicy =
          serviceLoaderPolicy == null
              ? NativeImageServiceLoaderPolicy.Selection.empty()
              : serviceLoaderPolicy;
    }

    RootScan(final Set<String> roots, final boolean declaresClassRoots) {
      this(
          roots,
          declaresClassRoots,
          false,
          Set.of(),
          roots,
          Set.of(),
          Set.of(),
          NativeImagePolicyRoots.ResourcePatternSelection.empty(),
          NativeImageServiceLoaderPolicy.Selection.empty());
    }

    EffectiveRoots effectiveRoots(
        final Set<String> provenServiceInterfaces, final boolean conservativeFallback) {
      return effectiveRoots(
          provenServiceInterfaces,
          conservativeFallback,
          NativeImageServiceLoaderPolicy.Selection.empty());
    }

    EffectiveRoots effectiveRoots(
        final Set<String> provenServiceInterfaces,
        final boolean conservativeFallback,
        final NativeImageServiceLoaderPolicy.Selection featureSelection) {
      final Set<String> featureRoots = featureRoots(featureSelection);
      final Set<String> effective = new LinkedHashSet<>(nonServiceRoots);
      effective.addAll(featureRoots);
      final Set<ServiceDescriptor> unprovenServices = new LinkedHashSet<>();
      final Set<String> unprovenRoots = new LinkedHashSet<>();
      for (final ServiceDescriptor descriptor : serviceDescriptors) {
        final boolean isProven =
            provenServiceInterfaces.contains(descriptor.serviceInterface())
                || descriptor.providers().stream().anyMatch(provenServiceInterfaces::contains);
        if (isProven) {
          effective.add(descriptor.serviceInterface());
          effective.addAll(descriptor.providers());
        } else if (conservativeFallback) {
          effective.add(descriptor.serviceInterface());
          effective.addAll(descriptor.providers());
          unprovenServices.add(descriptor);
          unprovenRoots.add(descriptor.serviceInterface());
          unprovenRoots.addAll(descriptor.providers());
        }
      }
      return new EffectiveRoots(effective, unprovenServices, unprovenRoots, featureRoots);
    }

    /* package */ RootScan withAdditionalClassRoots(final Set<String> additionalRoots) {
      if (additionalRoots.isEmpty()) {
        return this;
      }
      final Set<String> updatedRoots = new LinkedHashSet<>(roots);
      updatedRoots.addAll(additionalRoots);
      final Set<String> updatedNonServiceRoots = new LinkedHashSet<>(nonServiceRoots);
      updatedNonServiceRoots.addAll(additionalRoots);
      return new RootScan(
          updatedRoots,
          true,
          requiresArtifactRetention,
          serviceDescriptors,
          updatedNonServiceRoots,
          resourceProviders,
          consumedInputs,
          resourcePatterns,
          serviceLoaderPolicy);
    }

    private Set<String> featureRoots(final NativeImageServiceLoaderPolicy.Selection selection) {
      final Set<String> roots = new LinkedHashSet<>();
      if (!selection.enabled()) {
        return roots;
      }
      for (final ServiceDescriptor descriptor : serviceDescriptors) {
        if (!selection.excludedServices().contains(descriptor.serviceInterface())) {
          roots.add(descriptor.serviceInterface());
          descriptor.providers().stream()
              .filter(provider -> !selection.excludedProviders().contains(provider))
              .forEach(roots::add);
        }
      }
      return roots;
    }
  }

  private DependencyDynamicRoots() {}

  static RootScan scan(final java.nio.file.Path jar) throws IOException {
    return scan(jar, NativeImageScanContext.singleArchive(jar));
  }

  static RootScan scan(final java.nio.file.Path jar, final NativeImageScanContext scanContext)
      throws IOException {
    final ScanState state = new ScanState(jar, scanContext);
    try (JarFile archive = new JarFile(jar.toFile())) {
      final Enumeration<JarEntry> entries = archive.entries();
      while (entries.hasMoreElements()) {
        final JarEntry entry = entries.nextElement();
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

    /** Logical class names in the declaring archive. */
    private final Set<String> jarClasses;

    /** Whether this archive declares class roots. */
    private boolean declaresClassRoots;

    /** Whether resource metadata must survive class trimming. */
    private boolean requiresArtifactRetention;

    /** Creates mutable state for one archive using the invocation resource index. */
    private ScanState(final java.nio.file.Path jar, final NativeImageScanContext scanContext)
        throws IOException {
      this.scanContext = scanContext;
      this.jarClasses = scanContext.logicalClasses(java.util.Optional.of(jar));
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
      } else if (SPRING_METADATA.equals(name)) {
        declaresClassRoots = true;
        SpringMetadataRoots.readMetadata(
            archive.getInputStream(entry), nonServiceRoots, jarClasses);
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
