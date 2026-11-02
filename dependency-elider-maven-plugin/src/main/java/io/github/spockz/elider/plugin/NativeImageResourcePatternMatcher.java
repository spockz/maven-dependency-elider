/* WHY: Matches invocation resource patterns without mixing them with descriptor path lookup. */

package io.github.spockz.elider.plugin;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/** Applies whole-string Native Image resource selectors to indexed archive entries. */
final class NativeImageResourcePatternMatcher {
  private NativeImageResourcePatternMatcher() {
    throw new AssertionError("static resource pattern matcher");
  }

  /* package */ record Selector(Pattern pattern, String module, String group) {}

  /* package */ record BundleSelector(String module, String group, List<String> resourceBases) {
    /* package */
    BundleSelector(final String name, final String module, final String group) {
      this(module, group, NativeImageBundleResourceSupport.resourceBases(name));
    }
  }

  /* package */ static Selector regex(
      final String expression, final String module, final String source) throws IOException {
    final int separator = module == null ? expression.indexOf(':') : -1;
    final String pattern = separator < 0 ? expression : expression.substring(separator + 1);
    final String selectedModule = separator < 0 ? module : expression.substring(0, separator);
    try {
      return new Selector(Pattern.compile(pattern), selectedModule, source);
    } catch (final PatternSyntaxException exception) {
      throw new IOException("Malformed native-image resource pattern in " + source, exception);
    }
  }

  /* package */ static Selector glob(
      final String expression, final String module, final String source) throws IOException {
    try {
      return new Selector(
          NativeImageGlobPattern.compile(expression),
          module == null || module.isEmpty() ? null : module,
          source);
    } catch (final PatternSyntaxException exception) {
      throw new IOException("Malformed native-image resource glob in " + source, exception);
    }
  }

  /* package */ static boolean apply(
      final List<Selector> includes,
      final List<Selector> excludes,
      final List<BundleSelector> bundles,
      final Map<String, List<NativeImageArchiveInventory>> resourceIndex,
      final Set<String> roots,
      final Set<Path> providers)
      throws IOException {
    if (includes.isEmpty() && bundles.isEmpty()) {
      return false;
    }
    boolean addedClassRoot = false;
    for (final Map.Entry<String, List<NativeImageArchiveInventory>> resource :
        resourceIndex.entrySet().stream().sorted(Map.Entry.comparingByKey()).toList()) {
      final String resourceName = resource.getKey();
      final String logicalResourceName =
          NativeImageBundleResourceSupport.logicalResourceName(resourceName);
      if (!selected(includes, excludes, bundles, resourceName, logicalResourceName)) {
        continue;
      }
      for (final NativeImageArchiveInventory archive : resource.getValue()) {
        providers.add(archive.path());
        addedClassRoot |= addClassResourceRoot(resourceName, archive, roots);
      }
    }
    return addedClassRoot;
  }

  /* package */ static boolean apply(
      final List<Pattern> includes,
      final List<Pattern> excludes,
      final Map<String, List<NativeImageArchiveInventory>> resourceIndex,
      final Set<String> roots,
      final Set<Path> providers)
      throws IOException {
    return apply(
        includes.stream().map(pattern -> new Selector(pattern, null, "cli")).toList(),
        excludes.stream().map(pattern -> new Selector(pattern, null, "cli")).toList(),
        List.of(),
        resourceIndex,
        roots,
        providers);
  }

  private static boolean selected(
      final List<Selector> includes,
      final List<Selector> excludes,
      final List<BundleSelector> bundles,
      final String resourceName,
      final String logicalResourceName) {
    return includes.stream()
            .anyMatch(
                include ->
                    matches(include, resourceName)
                        && !excluded(excludes, include.group(), resourceName))
        || bundles.stream()
            .anyMatch(
                bundle ->
                    matches(bundle, logicalResourceName)
                        && !excluded(excludes, bundle.group(), resourceName));
  }

  private static boolean matches(final Selector selector, final String resourceName) {
    if (selector.module() != null && !"ALL-UNNAMED".equals(selector.module())) {
      return false;
    }
    final String entryName = stripDirectorySlash(resourceName);
    return selector.pattern().matcher(entryName).matches()
        || selector.pattern().matcher(entryName + "/").matches();
  }

  private static boolean matches(final BundleSelector selector, final String resourceName) {
    return (selector.module() == null || "ALL-UNNAMED".equals(selector.module()))
        && NativeImageBundleResourceSupport.matches(selector.resourceBases(), resourceName);
  }

  private static boolean excluded(
      final List<Selector> excludes, final String group, final String resourceName) {
    return excludes.stream()
        .anyMatch(exclude -> group.equals(exclude.group()) && matches(exclude, resourceName));
  }

  private static String stripDirectorySlash(final String resourceName) {
    return resourceName.endsWith("/")
        ? resourceName.substring(0, resourceName.length() - 1)
        : resourceName;
  }

  private static boolean addClassResourceRoot(
      final String resourceName, final NativeImageArchiveInventory archive, final Set<String> roots)
      throws IOException {
    if (!resourceName.endsWith(".class")) {
      return false;
    }
    final String logicalName = MultiReleaseClassInventory.logicalClassName(resourceName);
    final String className =
        logicalName.substring(0, logicalName.length() - ".class".length()).replace('/', '.');
    if (!archive.logicalClasses().contains(className)
        || !NativeImageDynamicRoots.isBinaryClassName(className)) {
      return false;
    }
    roots.add(className);
    return true;
  }
}
