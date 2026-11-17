// WHY: Verifies fixture repository mirror settings resolution and fallback behavior.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Tests {@link MavenFixtureRepositorySettings}. */
@SuppressWarnings("PMD.AtLeastOneConstructor")
final class MavenFixtureRepositorySettingsTest {
  /** Per-test temporary directory for generated settings files. */
  @TempDir private Path temporaryDirectory;

  @Test
  void settingsMirrorUsesConfiguredMavenCacheAndFallsBackToUserHome() throws Exception {
    final Path userHome = temporaryDirectory.resolve("user-home");
    final Path configuredRepository = temporaryDirectory.resolve("outer-maven-cache");
    final String configuredRepositoryUri =
        MavenFixtureRepositorySettings.cachedRepositoryUri(
            configuredRepository.toString(), userHome.toString());
    final String fallbackRepositoryUri =
        MavenFixtureRepositorySettings.cachedRepositoryUri(" ", userHome.toString());
    final Path configuredSettingsDirectory =
        Files.createDirectories(temporaryDirectory.resolve("configured-settings"));
    final Path fallbackSettingsDirectory =
        Files.createDirectories(temporaryDirectory.resolve("fallback-settings"));
    final String configuredSettings =
        Files.readString(
            MavenFixtureRepositorySettings.write(
                configuredSettingsDirectory, configuredRepositoryUri));
    final String fallbackSettings =
        Files.readString(
            MavenFixtureRepositorySettings.write(fallbackSettingsDirectory, fallbackRepositoryUri));

    assertAll(
        "Lifecycle mirrors use the selected local cache and block remote repositories",
        () ->
            assertThat(configuredRepositoryUri)
                .isEqualTo(configuredRepository.toUri().toASCIIString()),
        () -> assertThat(URI.create(configuredRepositoryUri).getScheme()).isEqualTo("file"),
        () ->
            assertThat(configuredSettings)
                .contains(
                    "<id>cached-local-mirror</id>",
                    "<mirrorOf>*</mirrorOf>",
                    "<url>" + configuredRepositoryUri + "</url>"),
        () ->
            assertThat(fallbackRepositoryUri)
                .isEqualTo(Path.of(userHome.toString(), ".m2/repository").toUri().toASCIIString()),
        () ->
            assertThat(fallbackSettings)
                .contains(
                    "<id>cached-local-mirror</id>",
                    "<mirrorOf>*</mirrorOf>",
                    "<url>" + fallbackRepositoryUri + "</url>"));
  }
}
