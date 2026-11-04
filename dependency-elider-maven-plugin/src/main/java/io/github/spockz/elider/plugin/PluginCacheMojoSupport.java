/* WHY: Shares producer-bound cache setup across plugin goals without using project versions. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.scanner.VulnerabilityCacheManager;
import io.github.spockz.elider.scanner.VulnerabilityCacheManager.CacheConfig;
import java.net.URI;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Optional;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.descriptor.PluginDescriptor;
import org.apache.maven.plugins.annotations.Component;
import org.apache.maven.plugins.annotations.Parameter;
import org.eclipse.aether.RepositorySystem;

/** Supports Maven goals that use the local advisory cache. */
abstract class PluginCacheMojoSupport extends AbstractMojo {
  /** Installed producer metadata, independent of the consumer project. */
  @Parameter(defaultValue = "${plugin}", readonly = true)
  private PluginDescriptor pluginDescriptor;

  /** Maven's resolver used only to locate exact-version sources artifacts. */
  @Component private RepositorySystem repositorySystem;

  /** Reused because SNAPSHOT identity hashing reads both installed JARs. */
  private PluginCacheProducerIdentityResolver.Resolution producerResolution;

  /** Creates the cache config using installed plugin identity. */
  protected final CacheConfig vulnerabilityCacheConfig(
      final Path cacheDirectory,
      final URI osvSnapshotUri,
      final URI cveListGitUri,
      final Duration ttl,
      final boolean forceRefresh,
      final boolean offline) {
    final PluginCacheProducerIdentityResolver.Resolution producer = cacheProducerResolution();
    return new CacheConfig(
        cacheDirectory,
        osvSnapshotUri,
        cveListGitUri,
        ttl,
        forceRefresh,
        offline,
        VulnerabilityCacheManager.bundledEmptySeed(),
        producer.identity(),
        producer.diagnostic());
  }

  /** Returns the installed producer identity shared by this goal's caches. */
  protected final PluginCacheProducerIdentityResolver.Resolution cacheProducerResolution() {
    if (producerResolution == null) {
      producerResolution = PluginCacheProducerIdentityResolver.resolve(pluginDescriptor);
    }
    return producerResolution;
  }

  /** Returns the Maven resolver when running inside the plugin container. */
  protected final Optional<MavenSourceClassifierResolver> sourceClassifierResolver() {
    return Optional.ofNullable(repositorySystem).map(MavenSourceClassifierResolver::new);
  }

  /** Builds trim settings with the shared installed-producer identity policy. */
  protected final ElisionAnalysisModel.TrimOptions trimOptions(
      final boolean enabled,
      final List<String> explicitRoots,
      final List<String> passThroughArtifacts,
      final boolean failOnUnsupportedModuleInfo,
      final int workers,
      final String mrjarStrategy,
      final DuplicateClassPolicy duplicateClasses) {
    final PluginCacheProducerIdentityResolver.Resolution producer = cacheProducerResolution();
    if (enabled && producer.identity().isEmpty() && getLog().isWarnEnabled()) {
      getLog()
          .warn(
              "Persistent trim cache is disabled: "
                  + producer.diagnostic().orElse("producer identity is unavailable"));
    }
    return new ElisionAnalysisModel.TrimOptions(
        enabled,
        explicitRoots,
        false,
        passThroughArtifacts,
        failOnUnsupportedModuleInfo,
        workers,
        mrjarStrategy,
        producer,
        duplicateClasses);
  }

  /** Creates shared support for plugin cache configuration. */
  protected PluginCacheMojoSupport() {
    super();
  }
}
