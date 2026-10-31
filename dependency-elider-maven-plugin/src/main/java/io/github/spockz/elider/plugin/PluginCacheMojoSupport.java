/* WHY: Shares producer-bound cache setup across plugin goals without using project versions. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.scanner.VulnerabilityCacheManager;
import io.github.spockz.elider.scanner.VulnerabilityCacheManager.CacheConfig;
import java.net.URI;
import java.nio.file.Path;
import java.time.Duration;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.descriptor.PluginDescriptor;
import org.apache.maven.plugins.annotations.Parameter;

/** Supports Maven goals that use the local advisory cache. */
abstract class PluginCacheMojoSupport extends AbstractMojo {
  /** Installed producer metadata, independent of the consumer project. */
  @Parameter(defaultValue = "${plugin}", readonly = true)
  private PluginDescriptor pluginDescriptor;

  /** Creates the cache config using installed plugin identity. */
  protected final CacheConfig vulnerabilityCacheConfig(
      final Path cacheDirectory,
      final URI osvSnapshotUri,
      final URI cveListGitUri,
      final Duration ttl,
      final boolean forceRefresh,
      final boolean offline) {
    final PluginCacheProducerIdentityResolver.Resolution producer =
        PluginCacheProducerIdentityResolver.resolve(pluginDescriptor);
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

  /** Creates shared support for plugin cache configuration. */
  protected PluginCacheMojoSupport() {
    super();
  }
}
