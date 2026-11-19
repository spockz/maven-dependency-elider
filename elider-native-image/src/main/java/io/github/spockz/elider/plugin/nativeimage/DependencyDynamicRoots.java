/* WHY: Finds class names declared by dependency-local dynamic loading
 * metadata before a JAR is trimmed, since ordinary bytecode references
 * cannot describe SPI or native-image lookups. */

package io.github.spockz.elider.plugin.nativeimage;

import io.github.spockz.elider.model.AsciiBinaryClassName;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/** Reads dependency-local service provider and supported Graal native-image roots. */
@SuppressWarnings({"PMD.CommentRequired", "PMD.CyclomaticComplexity", "PMD.AssignmentInOperand"})
public final class DependencyDynamicRoots {
  private static final String SERVICES = "META-INF/services/";
  private static final String SPRING_FACTORIES = "META-INF/spring.factories";
  private static final String SPRING_IMPORTS =
      "META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports";
  private static final RootScan NO_METADATA = new RootScan(Set.of(), false);
  private static final int MIN_DUPLICATE_ENTRIES = 2;

  /** Service provider declarations read from {@code META-INF/services/}. */
  public record ServiceDescriptor(String serviceInterface, Set<String> providers) {
    /** Validates and defensively copies a service descriptor. */
    public ServiceDescriptor {
      serviceInterface = java.util.Objects.requireNonNull(serviceInterface, "serviceInterface");
      providers = Set.copyOf(providers);
    }
  }

  /** Effective dynamic roots and unproven conservative entries for one invocation. */
  public record EffectiveRoots(
      Set<String> roots,
      Set<ServiceDescriptor> unprovenConservativeServices,
      Set<String> unprovenConservativeRoots,
      Set<String> featureRoots) {
    /** Defensively copies effective root sets. */
    public EffectiveRoots {
      roots = Set.copyOf(roots);
      unprovenConservativeServices = Set.copyOf(unprovenConservativeServices);
      unprovenConservativeRoots = Set.copyOf(unprovenConservativeRoots);
      featureRoots = Set.copyOf(featureRoots);
    }

    /** Returns whether any dynamic roots were declared. */
    public boolean declaresRoots() {
      return !roots.isEmpty();
    }
  }

  /** Dynamic root scan outcome for a single dependency archive. */
  public record RootScan(
      Set<String> roots,
      boolean declaresClassRoots,
      boolean requiresArtifactRetention,
      Set<ServiceDescriptor> serviceDescriptors,
      Set<String> nonServiceRoots,
      Set<java.nio.file.Path> resourceProviders,
      Set<NativeImageConsumedInput> consumedInputs,
      NativeImagePolicyRoots.ResourcePatternSelection resourcePatterns,
      NativeImageServiceLoaderPolicy.Selection serviceLoaderPolicy) {
    /** Validates and defensively copies a dependency archive root scan. */
    public RootScan {
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

    /** Creates a minimal root scan without service or resource metadata. */
    public RootScan(final Set<String> roots, final boolean declaresClassRoots) {
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

    /** Resolves effective dynamic roots using default service-loader policy. */
    public EffectiveRoots effectiveRoots(
        final Set<String> provenServiceInterfaces, final boolean conservativeFallback) {
      return effectiveRoots(
          provenServiceInterfaces,
          conservativeFallback,
          NativeImageServiceLoaderPolicy.Selection.empty());
    }

    /** Resolves effective dynamic roots under the given service-loader policy. */
    public EffectiveRoots effectiveRoots(
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

    /** Returns a copy of this scan augmented with additional class roots. */
    public RootScan withAdditionalClassRoots(final Set<String> additionalRoots) {
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

  /** Opens a sequential archive stream for duplicate metadata. */
  @FunctionalInterface
  @SuppressWarnings("PMD.CommentDefaultAccessModifier")
  interface ArchiveStreamFactory {
    InputStream open(java.nio.file.Path jar) throws IOException;
  }

  /** Scans a single dependency JAR for dynamic loading metadata. */
  public static RootScan scan(final java.nio.file.Path jar) throws IOException {
    return scan(jar, NativeImageScanContext.singleArchive(jar));
  }

  /** Scans a dependency JAR using an existing native-image scan context. */
  public static RootScan scan(
      final java.nio.file.Path jar, final NativeImageScanContext scanContext) throws IOException {
    return scan(jar, scanContext, Files::newInputStream);
  }

  /* package */ static RootScan scan(
      final java.nio.file.Path jar,
      final NativeImageScanContext scanContext,
      final ArchiveStreamFactory streamFactory)
      throws IOException {
    try (JarFile archive = new JarFile(jar.toFile())) {
      final List<JarEntry> metadataEntries =
          archive.stream()
              .filter(entry -> !entry.isDirectory() && isMetadataEntry(entry.getName()))
              .toList();
      if (metadataEntries.isEmpty()) {
        return NO_METADATA;
      }
      final ScanState state = new ScanState(scanContext);
      if (hasDuplicateNames(metadataEntries)) {
        scanDuplicateMetadata(archive, jar, streamFactory, state);
      } else {
        for (final JarEntry entry : metadataEntries) {
          state.scanEntry(archive, entry);
        }
      }
      return state.finish();
    }
  }

  private static boolean hasDuplicateNames(final List<JarEntry> entries) {
    if (entries.size() < MIN_DUPLICATE_ENTRIES) {
      return false;
    }
    final Set<String> names = HashSet.newHashSet(entries.size());
    for (final JarEntry entry : entries) {
      if (!names.add(entry.getName())) {
        return true;
      }
    }
    return false;
  }

  private static void scanDuplicateMetadata(
      final JarFile archive,
      final java.nio.file.Path jar,
      final ArchiveStreamFactory streamFactory,
      final ScanState state)
      throws IOException {
    final java.util.Map<String, Integer> entryOccurrences =
        new java.util.concurrent.ConcurrentHashMap<>();
    try (ZipInputStream stream = new ZipInputStream(streamFactory.open(jar))) {
      ZipEntry entry = stream.getNextEntry();
      while (entry != null) {
        if (!entry.isDirectory() && isMetadataEntry(entry.getName())) {
          final int occurrence = entryOccurrences.merge(entry.getName(), 1, Integer::sum) - 1;
          state.scanEntryBytes(archive, entry.getName(), stream.readAllBytes(), occurrence);
        }
        entry = stream.getNextEntry();
      }
    }
  }

  private static boolean isMetadataEntry(final String name) {
    return name.startsWith(SERVICES)
        || name.startsWith(NativeImageDynamicRoots.PREFIX)
        || SPRING_FACTORIES.equals(name)
        || SPRING_IMPORTS.equals(name);
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

    /** Dispatches one unique archive entry via selective {@link JarFile} access. */
    private void scanEntry(final JarFile archive, final JarEntry entry) throws IOException {
      final String name = entry.getName();
      if (name.startsWith(SERVICES)) {
        declaresClassRoots = true;
        readServiceDescriptor(name, archive.getInputStream(entry));
      } else if (name.startsWith(NativeImageDynamicRoots.PREFIX)
          && NativeImageDynamicRoots.isNativeImageClassConfig(name)) {
        declaresClassRoots = true;
        requiresArtifactRetention |=
            NativeImageClassConfig.readNativeImageClassConfig(
                NativeImageInput.archiveEntry(
                    archive, entry, NativeImageDescriptorKind.classConfigFor(name)),
                nonServiceRoots,
                null,
                resourcePatterns);
      } else if (name.startsWith(NativeImageDynamicRoots.PREFIX)
          && NativeImageDynamicRoots.isNativeImageResourceConfig(name)) {
        requiresArtifactRetention = true;
        NativeImageResourceConfig.readNativeImageResourceConfig(
            NativeImageInput.archiveEntry(archive, entry, NativeImageDescriptorKind.RESOURCES),
            nonServiceRoots,
            null,
            resourcePatterns);
      } else if (name.startsWith(NativeImageDynamicRoots.PREFIX) && name.endsWith(".properties")) {
        readNativeImageProperties(archive, entry, archive.getInputStream(entry));
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

    /** Dispatches one physical entry payload from a sequential duplicate-aware scan. */
    private void scanEntryBytes(
        final JarFile archive, final String name, final byte[] payload, final int physicalIndex)
        throws IOException {
      if (name.startsWith(SERVICES)) {
        declaresClassRoots = true;
        readServiceDescriptor(name, new ByteArrayInputStream(payload));
      } else if (name.startsWith(NativeImageDynamicRoots.PREFIX)
          && NativeImageDynamicRoots.isNativeImageClassConfig(name)) {
        declaresClassRoots = true;
        requiresArtifactRetention |=
            NativeImageClassConfig.readNativeImageClassConfig(
                NativeImageInput.archiveBytes(
                    archive,
                    name,
                    NativeImageDescriptorKind.classConfigFor(name),
                    payload,
                    physicalIndex),
                nonServiceRoots,
                null,
                resourcePatterns);
      } else if (name.startsWith(NativeImageDynamicRoots.PREFIX)
          && NativeImageDynamicRoots.isNativeImageResourceConfig(name)) {
        requiresArtifactRetention = true;
        NativeImageResourceConfig.readNativeImageResourceConfig(
            NativeImageInput.archiveBytes(
                archive, name, NativeImageDescriptorKind.RESOURCES, payload, physicalIndex),
            nonServiceRoots,
            null,
            resourcePatterns);
      } else if (name.startsWith(NativeImageDynamicRoots.PREFIX) && name.endsWith(".properties")) {
        readNativeImageProperties(archive, new JarEntry(name), new ByteArrayInputStream(payload));
      } else if (name.startsWith(NativeImageDynamicRoots.PREFIX)
          && !NativeImageDynamicRoots.isNativeImageSbom(name)
          && name.endsWith(".json")) {
        throw new IOException("Unsupported native-image class metadata: " + name);
      } else if (SPRING_FACTORIES.equals(name)) {
        declaresClassRoots |=
            SpringMetadataRoots.readFactories(new ByteArrayInputStream(payload), nonServiceRoots);
      } else if (SPRING_IMPORTS.equals(name)) {
        declaresClassRoots = true;
        SpringMetadataRoots.readImports(new ByteArrayInputStream(payload), nonServiceRoots, name);
      }
    }

    private void readServiceDescriptor(final String name, final InputStream stream)
        throws IOException {
      final String service = name.substring(SERVICES.length());
      if (service.isBlank() || service.contains("/")) {
        throw new IOException("Unsupported service descriptor path: " + name);
      }
      final Set<String> providers = new LinkedHashSet<>();
      try (BufferedReader reader =
          new BufferedReader(new InputStreamReader(stream, StandardCharsets.UTF_8))) {
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

    private void readNativeImageProperties(
        final JarFile archive, final JarEntry entry, final InputStream stream) throws IOException {
      final NativeImageDynamicRoots.PropertiesResult result;
      try (stream) {
        result =
            NativeImageDynamicRoots.readNativeImagePropertiesDetailed(
                archive,
                entry,
                stream,
                nonServiceRoots,
                scanContext,
                resourceProviders,
                consumedInputs);
      }
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
