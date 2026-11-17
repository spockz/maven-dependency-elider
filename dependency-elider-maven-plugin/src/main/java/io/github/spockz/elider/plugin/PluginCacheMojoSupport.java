/* WHY: Shares producer-bound cache setup across plugin goals without using project versions. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.advisory.VulnerabilityCacheManager;
import io.github.spockz.elider.advisory.VulnerabilityCacheManager.CacheConfig;
import java.io.File;
import java.net.URI;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecution;
import org.apache.maven.plugin.descriptor.PluginDescriptor;
import org.apache.maven.plugins.annotations.Parameter;

/** Supports Maven goals that use the local advisory cache. */
abstract class PluginCacheMojoSupport extends AbstractMojo {
  /** Installed producer metadata, independent of the consumer project. */
  @Parameter(defaultValue = "${plugin}", readonly = true)
  private PluginDescriptor pluginDescriptor;

  /** Reused because SNAPSHOT identity hashing reads both installed JARs. */
  private PluginCacheProducerIdentityResolver.Resolution producerResolution;

  /** Creates the cache config from Mojo parameters using installed plugin identity. */
  protected final CacheConfig vulnerabilityCacheConfig(
      final File cveCacheDirectory,
      final String osvSnapshotUri,
      final String cveListGitUri,
      final int cveCacheTtlHours,
      final boolean cveForceSync,
      final MavenSession session) {
    final Path cacheDirectory =
        cveCacheDirectory == null
            ? VulnerabilityCacheManager.defaultCacheDirectory()
            : cveCacheDirectory.toPath();
    final URI osvSource =
        osvSnapshotUri == null || osvSnapshotUri.isBlank() ? null : URI.create(osvSnapshotUri);
    final URI cveListGit =
        cveListGitUri == null || cveListGitUri.isBlank() ? null : URI.create(cveListGitUri);
    return vulnerabilityCacheConfig(
        cacheDirectory,
        osvSource,
        cveListGit,
        Duration.ofHours(cveCacheTtlHours),
        cveForceSync,
        session != null && session.isOffline());
  }

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

  /** Returns whether execution runs in {@code process-classes}. */
  protected static boolean trustedProcessClassesContext(final MojoExecution mojoExecution) {
    return mojoExecution != null
        && EliderPreparationState.source(mojoExecution) == MojoExecution.Source.LIFECYCLE
        && "process-classes".equals(mojoExecution.getLifecyclePhase());
  }

  /** Returns the installed producer identity shared by this goal's caches. */
  protected final PluginCacheProducerIdentityResolver.Resolution cacheProducerResolution() {
    if (producerResolution == null) {
      producerResolution = PluginCacheProducerIdentityResolver.resolve(pluginDescriptor);
    }
    return producerResolution;
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
