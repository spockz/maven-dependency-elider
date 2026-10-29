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

  /** Remote OSV Maven database snapshot URI. */
  @Parameter(
      property = "elide.osvSnapshotUri",
      defaultValue = "https://storage.googleapis.com/osv-vulnerabilities/Maven/all.zip")
  private String osvSnapshotUri;

  /** Remote Git repository URI for CVEList v5. */
  @Parameter(
      property = "elide.cveListGitUri",
      defaultValue = "https://github.com/CVEProject/cvelistV5.git")
  private String cveListGitUri;

  /** Maven session used to reject refreshes requested in offline mode. */
  @Parameter(defaultValue = "${session}", readonly = true)
  private MavenSession session;

  /** Creates the update goal. */
  public UpdateCveIndexMojo() {
    super();
  }

  @Override
  public void execute() throws MojoExecutionException {
    final URI osvSource = configuredOsvSource();
    final URI cveListGit = configuredCveListGit();
    requireOnlineSession();
    final CacheResult result = update(osvSource, cveListGit);
    if (getLog().isInfoEnabled()) {
      getLog()
          .info(
              "Loaded "
                  + result.mappings().size()
                  + " vulnerability mapping(s) from "
                  + result.source());
    }
  }

  private URI configuredOsvSource() throws MojoExecutionException {
    if (osvSnapshotUri == null || osvSnapshotUri.isBlank()) {
      throw new MojoExecutionException(
          "Set -Delide.osvSnapshotUri to an HTTP(S) vulnerability snapshot before updating");
    }
    return URI.create(osvSnapshotUri);
  }

  private URI configuredCveListGit() {
    if (cveListGitUri == null || cveListGitUri.isBlank()) {
      return null;
    }
    return URI.create(cveListGitUri);
  }

  private void requireOnlineSession() throws MojoExecutionException {
    if (session != null && session.isOffline()) {
      throw new MojoExecutionException(
          "Cannot update the vulnerability mapping index while Maven is offline");
    }
  }

  private CacheResult update(final URI osvSource, final URI cveListGit)
      throws MojoExecutionException {
    try {
      final CacheResult result =
          new VulnerabilityCacheManager()
              .load(
                  cacheConfig(osvSource, cveListGit),
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

  private CacheConfig cacheConfig(final URI osvSource, final URI cveListGit) {
    return new CacheConfig(
        cacheDirectory == null
            ? VulnerabilityCacheManager.defaultCacheDirectory()
            : cacheDirectory.toPath(),
        osvSource,
        cveListGit,
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
