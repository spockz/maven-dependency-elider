// WHY: Lets CI warm the shared vulnerability mapping cache without a Maven project.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.scanner.VulnerabilityCacheManager;
import io.github.spockz.elider.scanner.VulnerabilityCacheManager.CacheConfig;
import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.time.Duration;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;

/** Refreshes the configured cached vulnerability mapping index. */
@Mojo(name = "update-cve-index", requiresProject = false, threadSafe = true)
public final class UpdateCveIndexMojo extends AbstractMojo {
  @Parameter(property = "elide.cveCacheDirectory")
  private File cacheDirectory;

  @Parameter(property = "elide.cveCacheTtlHours", defaultValue = "24")
  private int ttlHours;

  @Parameter(property = "elide.cveForceSync", defaultValue = "false")
  private boolean forceSync;

  @Parameter(property = "elide.cveIndexUri")
  private String indexUri;

  @Parameter(defaultValue = "${session}", readonly = true)
  private MavenSession session;

  @Override
  public void execute() throws MojoExecutionException {
    final URI source = indexUri == null || indexUri.isBlank() ? null : URI.create(indexUri);
    if (source == null) {
      throw new MojoExecutionException(
          "Set -Delide.cveIndexUri to an HTTP(S) vulnerability mapping index before updating");
    }
    final CacheConfig config =
        new CacheConfig(
            cacheDirectory == null
                ? VulnerabilityCacheManager.defaultCacheDirectory()
                : cacheDirectory.toPath(),
            source,
            Duration.ofHours(ttlHours),
            forceSync,
            session != null && session.isOffline(),
            VulnerabilityCacheManager.bundledEmptySeed());
    try {
      final VulnerabilityCacheManager.CacheResult result =
          new VulnerabilityCacheManager().load(config);
      result.refreshFailure().ifPresent(message -> getLog().warn(message));
      getLog()
          .info(
              "Loaded "
                  + result.mappings().size()
                  + " vulnerability mapping(s) from "
                  + result.source());
    } catch (final IOException | IllegalArgumentException exception) {
      throw new MojoExecutionException("Could not load vulnerability mapping index", exception);
    }
  }
}
