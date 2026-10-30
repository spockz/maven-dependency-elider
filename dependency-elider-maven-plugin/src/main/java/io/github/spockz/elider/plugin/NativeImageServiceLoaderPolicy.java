/* WHY: Holds service-loader policy until every candidate archive has been scanned. */

package io.github.spockz.elider.plugin;

import java.io.IOException;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.jar.JarEntry;

/** Parses invocation-wide Graal ServiceLoader feature settings. */
final class NativeImageServiceLoaderPolicy {
  /** Exact option enabling automatic service registration. */
  private static final String ENABLE = "-H:+UseServiceLoaderFeature";

  /** Exact option disabling automatic service registration. */
  private static final String DISABLE = "-H:-UseServiceLoaderFeature";

  /** Unsupported unqualified toggle spelling. */
  private static final String TOGGLE_BASE = "-H:UseServiceLoaderFeature";

  /** Exact service exclusion option name. */
  private static final String EXCLUDE_SERVICES = "-H:ServiceLoaderFeatureExcludeServices";

  /** Exact provider exclusion option name. */
  private static final String EXCLUDE_PROVIDERS = "-H:ServiceLoaderFeatureExcludeServiceProviders";

  /* package */ record Selection(
      boolean enabled, Set<String> excludedServices, Set<String> excludedProviders) {
    Selection {
      excludedServices = Set.copyOf(excludedServices);
      excludedProviders = Set.copyOf(excludedProviders);
    }

    /* package */ static Selection empty() {
      return new Selection(false, Set.of(), Set.of());
    }
  }

  /** Accumulates one archive's options before handing immutable state to the scan. */
  /* package */ static final class Builder {
    /** Whether any candidate enables the feature. */
    private boolean enabled;

    /** Service types excluded from the feature-derived root set. */
    private final Set<String> excludedServices = new LinkedHashSet<>();

    /** Provider types excluded from the feature-derived root set. */
    private final Set<String> excludedProviders = new LinkedHashSet<>();

    /* package */ Selection snapshot() {
      return new Selection(enabled, excludedServices, excludedProviders);
    }

    /* package */ void merge(final Selection selection) {
      enabled |= selection.enabled();
      excludedServices.addAll(selection.excludedServices());
      excludedProviders.addAll(selection.excludedProviders());
    }

    /* package */ void enable() {
      enabled = true;
    }

    /* package */ void excludeServices(final Set<String> services) {
      excludedServices.addAll(services);
    }

    /* package */ void excludeProviders(final Set<String> providers) {
      excludedProviders.addAll(providers);
    }
  }

  private NativeImageServiceLoaderPolicy() {
    throw new AssertionError("static service-loader policy reader");
  }

  /* package */ static boolean read(
      final String argument, final JarEntry entry, final Builder selection) throws IOException {
    return readToggle(argument, entry, selection) || readExclusion(argument, entry, selection);
  }

  private static boolean readToggle(
      final String argument, final JarEntry entry, final Builder selection) throws IOException {
    if (ENABLE.equals(argument)) {
      selection.enable();
      return true;
    }
    if (DISABLE.equals(argument)) {
      return true;
    }
    if (TOGGLE_BASE.equals(argument)
        || argument.startsWith(ENABLE + "=")
        || argument.startsWith(DISABLE + "=")
        || argument.startsWith(TOGGLE_BASE + "=")) {
      throw new IOException("Malformed ServiceLoader feature toggle in " + entry.getName());
    }
    return false;
  }

  private static boolean readExclusion(
      final String argument, final JarEntry entry, final Builder selection) throws IOException {
    if (EXCLUDE_SERVICES.equals(argument) || EXCLUDE_PROVIDERS.equals(argument)) {
      throw new IOException("ServiceLoader policy option has no value in " + entry.getName());
    }
    if (argument.startsWith(EXCLUDE_SERVICES + "=")) {
      selection.excludeServices(
          NativeImageClassRootParsing.parseClassNames(
              argument.substring(EXCLUDE_SERVICES.length() + 1), entry));
      return true;
    }
    if (argument.startsWith(EXCLUDE_PROVIDERS + "=")) {
      selection.excludeProviders(
          NativeImageClassRootParsing.parseClassNames(
              argument.substring(EXCLUDE_PROVIDERS.length() + 1), entry));
      return true;
    }
    return false;
  }

  /* package */ static Selection merge(final Iterable<Selection> selections) {
    final Builder builder = new Builder();
    for (final Selection selection : selections) {
      builder.merge(selection);
    }
    return builder.snapshot();
  }
}
