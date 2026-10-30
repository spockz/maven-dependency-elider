/* WHY: Finds class names declared by dependency-local dynamic loading metadata before a JAR is
 * trimmed, since ordinary bytecode references cannot describe SPI or native-image lookups. */

package io.github.spockz.elider.plugin;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Enumeration;
import java.util.LinkedHashSet;
import java.util.Properties;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

/** Reads dependency-local service provider and supported Graal native-image roots. */
@SuppressWarnings({
  "PMD.CommentRequired",
  "PMD.CommentDefaultAccessModifier",
  "PMD.CognitiveComplexity",
  "PMD.CyclomaticComplexity",
  "PMD.AvoidInstantiatingObjectsInLoops",
  "PMD.AssignmentInOperand",
  "PMD.AvoidDeeplyNestedIfStmts",
  "PMD.GodClass"
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
      Set<String> unprovenConservativeRoots) {
    EffectiveRoots {
      roots = Set.copyOf(roots);
      unprovenConservativeServices = Set.copyOf(unprovenConservativeServices);
      unprovenConservativeRoots = Set.copyOf(unprovenConservativeRoots);
    }

    boolean declaresRoots() {
      return !roots.isEmpty();
    }
  }

  record RootScan(
      Set<String> roots,
      boolean declaresClassRoots,
      Set<ServiceDescriptor> serviceDescriptors,
      Set<String> nonServiceRoots,
      java.util.List<NativeImageDynamicRoots.UnsupportedArgument> unsupportedNativeImageArgs,
      String nativeImagePolicy) {
    RootScan {
      roots = Set.copyOf(roots);
      serviceDescriptors = Set.copyOf(serviceDescriptors);
      nonServiceRoots = Set.copyOf(nonServiceRoots);
      unsupportedNativeImageArgs = java.util.List.copyOf(unsupportedNativeImageArgs);
    }

    RootScan(final Set<String> roots, final boolean declaresClassRoots) {
      this(roots, declaresClassRoots, Set.of(), roots, java.util.List.of(), "default");
    }

    boolean requiresPassThrough() {
      return !unsupportedNativeImageArgs.isEmpty();
    }

    EffectiveRoots effectiveRoots(
        final Set<String> provenServiceInterfaces, final boolean conservativeFallback) {
      final Set<String> effective = new LinkedHashSet<>(nonServiceRoots);
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
      return new EffectiveRoots(effective, unprovenServices, unprovenRoots);
    }
  }

  private DependencyDynamicRoots() {}

  static RootScan scan(final java.nio.file.Path jar) throws IOException {
    return scan(jar, Set.of(), true);
  }

  static RootScan scan(
      final java.nio.file.Path jar,
      final Set<String> allowedArguments,
      final boolean failOnUnsupported)
      throws IOException {
    final Set<String> roots = new LinkedHashSet<>();
    final Set<String> nonServiceRoots = new LinkedHashSet<>();
    final Set<ServiceDescriptor> serviceDescriptors = new LinkedHashSet<>();
    boolean declaresClassRoots = false;
    final java.util.List<NativeImageDynamicRoots.UnsupportedArgument> unsupportedNativeImageArgs =
        new java.util.ArrayList<>();
    try (JarFile archive = new JarFile(jar.toFile())) {
      final Set<String> jarClasses =
          archive.stream()
              .map(JarEntry::getName)
              .filter(name -> name.endsWith(".class"))
              .map(name -> name.substring(0, name.length() - ".class".length()).replace('/', '.'))
              .collect(java.util.stream.Collectors.toSet());
      final Enumeration<JarEntry> entries = archive.entries();
      while (entries.hasMoreElements()) {
        final JarEntry entry = entries.nextElement();
        if (entry.isDirectory()) {
          continue;
        }
        final String name = entry.getName();
        if (name.startsWith(SERVICES)) {
          declaresClassRoots = true;
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
                if (!provider.matches("[A-Za-z_$][A-Za-z0-9_$]*(\\.[A-Za-z_$][A-Za-z0-9_$]*)*")) {
                  throw new IOException("Malformed service provider in " + name + ": " + provider);
                }
                providers.add(provider);
              }
            }
          }
          serviceDescriptors.add(new ServiceDescriptor(service, providers));
          roots.add(service);
          roots.addAll(providers);
        } else if (name.startsWith(NativeImageDynamicRoots.PREFIX)
            && NativeImageDynamicRoots.isNativeImageClassConfig(name)) {
          declaresClassRoots = true;
          NativeImageClassConfig.readNativeImageClassConfig(archive, name, nonServiceRoots);
        } else if (name.startsWith(NativeImageDynamicRoots.PREFIX)
            && NativeImageDynamicRoots.isNativeImageResourceConfig(name)) {
          NativeImageResourceConfig.readNativeImageResourceConfig(archive, name, nonServiceRoots);
        } else if (name.startsWith(NativeImageDynamicRoots.PREFIX)
            && name.endsWith(".properties")) {
          final NativeImageDynamicRoots.PropertiesResult propertiesResult =
              NativeImageDynamicRoots.readNativeImagePropertiesDetailed(
                  archive, entry, nonServiceRoots, allowedArguments, failOnUnsupported);
          declaresClassRoots |= propertiesResult.declaresClassRoots();
          unsupportedNativeImageArgs.addAll(propertiesResult.unsupportedArguments());
        } else if (name.startsWith(NativeImageDynamicRoots.PREFIX)
            && !NativeImageDynamicRoots.isNativeImageSbom(name)
            && name.endsWith(".json")) {
          throw new IOException("Unsupported native-image class metadata: " + name);
        } else if (SPRING_FACTORIES.equals(name)) {
          declaresClassRoots |= readSpringFactories(archive.getInputStream(entry), nonServiceRoots);
        } else if (SPRING_IMPORTS.equals(name)) {
          declaresClassRoots = true;
          readSpringImports(archive.getInputStream(entry), nonServiceRoots, name);
        } else if (SPRING_METADATA.equals(name)) {
          declaresClassRoots = true;
          readSpringMetadata(archive.getInputStream(entry), nonServiceRoots, jarClasses);
        }
      }
    }
    roots.addAll(nonServiceRoots);
    return new RootScan(
        roots,
        declaresClassRoots,
        serviceDescriptors,
        nonServiceRoots,
        java.util.List.copyOf(unsupportedNativeImageArgs),
        "fail="
            + failOnUnsupported
            + ";allowed="
            + String.join(",", new java.util.TreeSet<>(allowedArguments)));
  }

  private static boolean readSpringFactories(final InputStream input, final Set<String> roots)
      throws IOException {
    final Properties factories = new Properties();
    try (InputStream stream = input) {
      factories.load(stream);
    }
    for (final String key : factories.stringPropertyNames()) {
      final String factory = key.trim();
      if (!isBinaryClassName(factory)) {
        throw new IOException("Malformed Spring factory interface name: " + key);
      }
      roots.add(factory);
      for (final String provider : factories.getProperty(key).split(",")) {
        final String className = provider.trim();
        if (!isBinaryClassName(className)) {
          throw new IOException("Malformed Spring factory implementation: " + provider);
        }
        roots.add(className);
      }
    }
    return true;
  }

  private static void readSpringImports(
      final InputStream input, final Set<String> roots, final String entryName) throws IOException {
    try (BufferedReader reader =
        new BufferedReader(new InputStreamReader(input, StandardCharsets.UTF_8))) {
      String line;
      while ((line = reader.readLine()) != null) {
        final String className = line.split("#", 2)[0].trim();
        if (!className.isEmpty()) {
          if (!isBinaryClassName(className)) {
            throw new IOException("Malformed Spring AutoConfiguration import in " + entryName);
          }
          roots.add(className);
        }
      }
    }
  }

  private static void readSpringMetadata(
      final InputStream input, final Set<String> roots, final Set<String> jarClasses)
      throws IOException {
    final Properties metadata = new Properties();
    try (InputStream stream = input) {
      metadata.load(stream);
    }
    for (final String propertyKey : metadata.stringPropertyNames()) {
      final String value = metadata.getProperty(propertyKey);
      if (jarClasses.contains(propertyKey)) {
        if (!value.isEmpty()) {
          throw new IOException("Unsupported Spring autoconfigure metadata key: " + propertyKey);
        }
        roots.add(propertyKey);
        continue;
      }
      final String marker = metadataMarker(propertyKey, jarClasses);
      if (marker == null) {
        throw new IOException("Unsupported Spring autoconfigure metadata key: " + propertyKey);
      }
      final int conditionStart = propertyKey.lastIndexOf(marker);
      final String owner = propertyKey.substring(0, conditionStart);
      if (!jarClasses.contains(owner)) {
        throw new IOException("Spring autoconfigure metadata owner is not in the JAR: " + owner);
      }
      roots.add(owner);
      if (marker.endsWith("Before") || marker.endsWith("After")) {
        for (final String candidate : value.split("[,;\\s]+")) {
          if (!isBinaryClassName(candidate)) {
            throw new IOException("Unsupported Spring autoconfigure metadata value: " + candidate);
          }
          roots.add(candidate);
        }
      } else if (marker.endsWith("Order")) {
        try {
          Integer.parseInt(value);
        } catch (final NumberFormatException exception) {
          throw new IOException(
              "Unsupported Spring autoconfigure order value: " + value, exception);
        }
      } else if (marker.endsWith("Conditional")
          && classValuedCondition(propertyKey.substring(conditionStart + marker.length()))
          && !value.isBlank()) {
        for (final String candidate : value.split("[,;\\s]+")) {
          if (!isBinaryClassName(candidate)) {
            throw new IOException("Unsupported Spring autoconfigure class value: " + candidate);
          }
          roots.add(candidate);
        }
      } else if (marker.endsWith("Conditional")
          && propertyKey.endsWith(".ConditionalOnWebApplication")
          && !Set.of("", "SERVLET", "REACTIVE").contains(value)) {
        throw new IOException("Unsupported Spring web application condition value: " + value);
      }
    }
  }

  private static boolean classValuedCondition(final String condition) {
    return condition.startsWith("OnClass")
        || condition.startsWith("OnMissingClass")
        || condition.startsWith("OnBean")
        || condition.startsWith("OnMissingBean")
        || condition.startsWith("OnSingleCandidate");
  }

  private static String metadataMarker(final String key, final Set<String> jarClasses) {
    for (final String suffix :
        Set.of(".AutoConfigureBefore", ".AutoConfigureAfter", ".AutoConfigureOrder")) {
      if (key.endsWith(suffix)) {
        return suffix;
      }
    }
    final int conditionIndex = key.lastIndexOf(".Conditional");
    if (conditionIndex >= 0
        && jarClasses.contains(key.substring(0, conditionIndex))
        && key.substring(conditionIndex + 1).matches("Conditional[A-Za-z0-9_$]+")) {
      return ".Conditional";
    }
    return null;
  }

  private static boolean isBinaryClassName(final String name) {
    return name.matches("[A-Za-z_$][A-Za-z0-9_$]*(\\.[A-Za-z_$][A-Za-z0-9_$]*)*");
  }
}
