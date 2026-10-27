// WHY: Lets CI warm the shared vulnerability mapping cache without a Maven project.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.VulnerabilitySymbolMapping;
import io.github.spockz.elider.scanner.VulnerabilityCacheManager;
import io.github.spockz.elider.scanner.VulnerabilityCacheManager.CacheConfig;
import io.github.spockz.elider.scanner.VulnerabilityCacheManager.CacheResult;
import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.time.Duration;
import java.util.List;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;

/** Refreshes the configured cached vulnerability mapping index. */
@Mojo(name = "update-cve-index", requiresProject = false, threadSafe = true)
public final class UpdateCveIndexMojo extends AbstractMojo {
  /** Optional directory containing the local vulnerability mapping cache. */
  @Parameter(property = "elide.cveCacheDirectory")
  private File cacheDirectory;

  /** Maximum age accepted by normal cache readers before refreshing. */
  @Parameter(property = "elide.cveCacheTtlHours", defaultValue = "24")
  private int ttlHours;

  /** Configured HTTP(S) index used for the forced refresh. */
  @Parameter(property = "elide.cveIndexUri")
  private String indexUri;

  /** Maven session used to reject refreshes requested in offline mode. */
  @Parameter(defaultValue = "${session}", readonly = true)
  private MavenSession session;

  /** Creates the update goal. */
  public UpdateCveIndexMojo() {
    super();
  }

  @Override
  public void execute() throws MojoExecutionException {
    final URI source = configuredSource();
    requireOnlineSession();
    final CacheResult result = update(source);
    if (getLog().isInfoEnabled()) {
      getLog()
          .info(
              "Loaded "
                  + result.mappings().size()
                  + " vulnerability mapping(s) from "
                  + result.source());
    }
  }

  private URI configuredSource() throws MojoExecutionException {
    if (indexUri == null || indexUri.isBlank()) {
      throw new MojoExecutionException(
          "Set -Delide.cveIndexUri to an HTTP(S) vulnerability mapping index before updating");
    }
    return URI.create(indexUri);
  }

  private void requireOnlineSession() throws MojoExecutionException {
    if (session != null && session.isOffline()) {
      throw new MojoExecutionException(
          "Cannot update the vulnerability mapping index while Maven is offline");
    }
  }

  private CacheResult update(final URI source) throws MojoExecutionException {
    try {
      final CacheResult result =
          new VulnerabilityCacheManager()
              .load(
                  cacheConfig(source),
                  mappings -> validateMappings(mappings, "downloaded vulnerability index"));
      if (result.refreshFailure().isPresent()) {
        throw new MojoExecutionException(
            "Could not update vulnerability mapping index: "
                + result.refreshFailure().orElseThrow());
      }
      validateMappings(result.mappings(), "cached index");
      return result;
    } catch (final IOException | IllegalArgumentException exception) {
      throw new MojoExecutionException("Could not load vulnerability mapping index", exception);
    }
  }

  private CacheConfig cacheConfig(final URI source) {
    return new CacheConfig(
        cacheDirectory == null
            ? VulnerabilityCacheManager.defaultCacheDirectory()
            : cacheDirectory.toPath(),
        source,
        Duration.ofHours(ttlHours),
        true,
        false,
        VulnerabilityCacheManager.bundledEmptySeed());
  }

  private void validateMappings(
      final List<VulnerabilitySymbolMapping> mappings, final String source) throws IOException {
    MavenVersionRangeMatcher.validateDownloadedMappings(mappings, source);
  }
}
