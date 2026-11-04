// WHY: Verifies effective Maven target selection separately from the active-runtime JDK class
// table.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.model.Build;
import org.apache.maven.model.building.DefaultModelBuilderFactory;
import org.apache.maven.model.building.DefaultModelBuildingRequest;
import org.apache.maven.model.building.ModelBuildingException;
import org.apache.maven.project.MavenProject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Tests effective Maven target selection. */
@SuppressWarnings("PMD.AtLeastOneConstructor")
final class MavenCompilerTargetSelectionTest {
  /** Maven property used to select the configured target. */
  private static final String TARGET_PROPERTY = "maven.compiler.target";

  /** Javac option representing the selected target. */
  private static final String TARGET_OPTION = "-target";

  /** Javac option representing the selected release. */
  private static final String RELEASE_OPTION = "--release";

  /** Holds the model directories used by the Maven POM fixtures. */
  @TempDir private Path temporaryDirectory;

  @Test
  void implicitDefaultCompileExecutionOverridesDefaultsAndIgnoresTestCompile()
      throws IOException, ModelBuildingException {
    final MavenProject project =
        effectiveProject(
            "implicit-default-compile.xml",
            """
            <project xmlns="http://maven.apache.org/POM/4.0.0">
              <modelVersion>4.0.0</modelVersion>
              <groupId>example</groupId><artifactId>compiler-target</artifactId><version>1</version>
              <properties><maven.compiler.target>8</maven.compiler.target><target.release.override>17</target.release.override></properties>
              <build>
                <pluginManagement><plugins><plugin>
                  <groupId>org.apache.maven.plugins</groupId><artifactId>maven-compiler-plugin</artifactId>
                  <version>3.13.0</version><configuration><target>8</target></configuration>
                </plugin></plugins></pluginManagement>
                <plugins><plugin>
                  <groupId>org.apache.maven.plugins</groupId><artifactId>maven-compiler-plugin</artifactId>
                  <version>3.13.0</version><configuration><target>11</target></configuration>
                  <executions>
                    <execution><id>default-compile</id><configuration><target>${target.release.override}</target></configuration></execution>
                    <execution><id>test-only</id><goals><goal>testCompile</goal></goals>
                      <configuration><target>8</target></configuration>
                    </execution>
                  </executions>
                </plugin></plugins>
              </build>
            </project>
            """);

    assertAll(
        "Maven's implicit compile binding uses its matching execution configuration",
        () ->
            assertThat(MavenCompilerSettings.platformReleaseOptions(project, null))
                .containsExactly(TARGET_OPTION, "17"),
        () ->
            assertThat(MavenCompilerSettings.analysisTargetOptions(project, (MavenSession) null))
                .containsExactly(TARGET_OPTION, "17"));
  }

  @Test
  void activeEffectivePluginConfigurationIsNotMergedWithManagementAgain()
      throws IOException, ModelBuildingException {
    final MavenProject project =
        effectiveProject(
            "plugin-management-override.xml",
            """
            <project xmlns="http://maven.apache.org/POM/4.0.0">
              <modelVersion>4.0.0</modelVersion>
              <groupId>example</groupId><artifactId>compiler-target</artifactId><version>1</version>
              <build>
                <pluginManagement><plugins><plugin>
                  <groupId>org.apache.maven.plugins</groupId><artifactId>maven-compiler-plugin</artifactId>
                  <version>3.13.0</version><configuration><target>8</target>
                    <compilerArgs combine.children="append"><arg>-Xlint:all</arg></compilerArgs>
                  </configuration>
                </plugin></plugins></pluginManagement>
                <plugins><plugin>
                  <groupId>org.apache.maven.plugins</groupId><artifactId>maven-compiler-plugin</artifactId>
                  <version>3.13.0</version><configuration><source>8</source><target>11</target>
                    <compilerArgs combine.children="append"/>
                  </configuration>
                </plugin></plugins>
              </build>
            </project>
            """);

    assertAll(
        "the effective active plugin config overrides management without "
            + "duplicate appended arguments",
        () ->
            assertThat(MavenCompilerSettings.platformReleaseOptions(project, null))
                .containsExactly("-source", "8", TARGET_OPTION, "11"),
        () ->
            assertThat(MavenCompilerSettings.options(project, null, List.of()))
                .containsExactly("-source", "8", TARGET_OPTION, "11"));
  }

  @Test
  void activeCompileExecutionsWithDifferentNotationCanSelectTheSameTarget()
      throws IOException, ModelBuildingException {
    final MavenProject project =
        effectiveProject(
            "same-target-different-notation.xml",
            """
            <project xmlns="http://maven.apache.org/POM/4.0.0">
              <modelVersion>4.0.0</modelVersion>
              <groupId>example</groupId><artifactId>compiler-target</artifactId><version>1</version>
              <build><plugins><plugin>
                <groupId>org.apache.maven.plugins</groupId><artifactId>maven-compiler-plugin</artifactId>
                <version>3.13.0</version>
                <executions>
                  <execution><id>default-compile</id><configuration><release>17</release></configuration></execution>
                  <execution><id>additional-compile</id><goals><goal>compile</goal></goals>
                    <configuration><target>17</target></configuration>
                  </execution>
                </executions>
              </plugin></plugins></build>
            </project>
            """);

    assertAll(
        "release and target notation select the same analysis release",
        () ->
            assertThat(MavenCompilerSettings.analysisTargetOptions(project, (MavenSession) null))
                .containsExactly(TARGET_OPTION, "17"),
        () ->
            assertThat(
                    TrimPlatform.targetReleaseFromOptions(
                        MavenCompilerSettings.analysisTargetOptions(project, (MavenSession) null)))
                .isEqualTo(17));
  }

  @Test
  void consistentReleaseAndSourceTargetSettingsResolveToRelease()
      throws IOException, ModelBuildingException {
    final MavenProject project =
        effectiveProject(
            "consistent-release-source-target.xml",
            """
            <project xmlns="http://maven.apache.org/POM/4.0.0">
              <modelVersion>4.0.0</modelVersion>
              <groupId>example</groupId><artifactId>compiler-target</artifactId><version>1</version>
              <properties>
                <maven.compiler.release>21</maven.compiler.release>
                <maven.compiler.source>21</maven.compiler.source>
                <maven.compiler.target>21</maven.compiler.target>
              </properties>
            </project>
            """);

    assertAll(
        "consistent release and source/target resolve to --release",
        () ->
            assertThat(MavenCompilerSettings.options(project, null, List.of()))
                .containsExactly(RELEASE_OPTION, "21"),
        () ->
            assertThat(MavenCompilerSettings.releaseIdentity(project, (MavenSession) null))
                .containsExactly(RELEASE_OPTION, "21"),
        () ->
            assertThat(MavenCompilerSettings.platformReleaseOptions(project, null))
                .containsExactly(RELEASE_OPTION, "21"),
        () ->
            assertThat(MavenCompilerSettings.analysisTargetOptions(project, (MavenSession) null))
                .containsExactly(RELEASE_OPTION, "21"));
  }

  @Test
  void conflictingReleaseAndSourceOrTargetRejectsAttributionAndIdentity()
      throws IOException, ModelBuildingException {
    final MavenProject project =
        effectiveProject(
            "conflicting-release-source-target.xml",
            """
            <project xmlns="http://maven.apache.org/POM/4.0.0">
              <modelVersion>4.0.0</modelVersion>
              <groupId>example</groupId><artifactId>compiler-target</artifactId><version>1</version>
              <properties>
                <maven.compiler.release>21</maven.compiler.release>
                <maven.compiler.source>17</maven.compiler.source>
                <maven.compiler.target>21</maven.compiler.target>
              </properties>
            </project>
            """);

    assertAll(
        "conflicting release and source/target reject attribution and identity",
        () ->
            assertThatThrownBy(() -> MavenCompilerSettings.options(project, null, List.of()))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("Cannot attribute source with both compiler release and source/target"),
        () ->
            assertThatThrownBy(
                    () -> MavenCompilerSettings.releaseIdentity(project, (MavenSession) null))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("Cannot identify compiler release with both release and source/target"));
  }

  @Test
  void managedDefaultCompileExecutionConfiguresTheImplicitCompilerGoal()
      throws IOException, ModelBuildingException {
    final MavenProject project =
        effectiveProject(
            "managed-default-compile.xml",
            """
            <project xmlns="http://maven.apache.org/POM/4.0.0">
              <modelVersion>4.0.0</modelVersion>
              <groupId>example</groupId><artifactId>compiler-target</artifactId><version>1</version>
              <build><pluginManagement><plugins><plugin>
                <groupId>org.apache.maven.plugins</groupId><artifactId>maven-compiler-plugin</artifactId>
                <version>3.13.0</version><configuration><source>8</source><target>8</target></configuration>
                <executions><execution><id>default-compile</id><configuration><target>17</target></configuration></execution></executions>
              </plugin></plugins></pluginManagement></build>
            </project>
            """);

    assertAll(
        "pluginManagement defaults configure the implicit lifecycle compiler execution",
        () ->
            assertThat(MavenCompilerSettings.platformReleaseOptions(project, null))
                .containsExactly("-source", "8", TARGET_OPTION, "17"),
        () ->
            assertThat(MavenCompilerSettings.analysisTargetOptions(project, (MavenSession) null))
                .containsExactly(TARGET_OPTION, "17"));
  }

  @Test
  void differentActiveCompileExecutionsDoNotCollapseToOneTarget()
      throws IOException, ModelBuildingException {
    final MavenProject project =
        effectiveProject(
            "conflicting-compile-executions.xml",
            """
            <project xmlns="http://maven.apache.org/POM/4.0.0">
              <modelVersion>4.0.0</modelVersion>
              <groupId>example</groupId><artifactId>compiler-target</artifactId><version>1</version>
              <build><plugins><plugin>
                <groupId>org.apache.maven.plugins</groupId><artifactId>maven-compiler-plugin</artifactId>
                <version>3.13.0</version>
                <executions>
                  <execution><id>default-compile</id><configuration><target>17</target></configuration></execution>
                  <execution><id>another-compile</id><goals><goal>compile</goal></goals>
                    <configuration><target>11</target></configuration>
                  </execution>
                </executions>
              </plugin></plugins></build>
            </project>
            """);

    assertThatThrownBy(() -> MavenCompilerSettings.platformReleaseOptions(project, null))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("Maven compiler executions select different target releases");
  }

  @Test
  void capturedTargetPropertyPrecedenceIsUserThenSystemThenProject() throws IOException {
    final MavenProject project = new MavenProject();
    project.setBuild(new Build());
    project.getProperties().setProperty(TARGET_PROPERTY, "8");
    final AnalysisEnvironment userEnvironment =
        environment(Map.of(TARGET_PROPERTY, "17"), Map.of(TARGET_PROPERTY, "11"));
    final AnalysisEnvironment systemEnvironment =
        environment(Map.of(TARGET_PROPERTY, "17"), Map.of());

    assertAll(
        "target properties use captured Maven user, then system, then project values",
        () ->
            assertThat(MavenCompilerSettings.analysisTargetOptions(project, userEnvironment))
                .containsExactly(TARGET_OPTION, "11"),
        () ->
            assertThat(MavenCompilerSettings.analysisTargetOptions(project, systemEnvironment))
                .containsExactly(TARGET_OPTION, "17"));
  }

  private MavenProject effectiveProject(final String fileName, final String pomXml)
      throws IOException, ModelBuildingException {
    final Path pom = temporaryDirectory.resolve(fileName);
    Files.writeString(pom, pomXml);
    final DefaultModelBuildingRequest request = new DefaultModelBuildingRequest();
    request.setPomFile(pom.toFile()).setSystemProperties(System.getProperties());
    return new MavenProject(
        new DefaultModelBuilderFactory().newInstance().build(request).getEffectiveModel());
  }

  private AnalysisEnvironment environment(
      final Map<String, String> system, final Map<String, String> user) {
    return new AnalysisEnvironment(
        system, user, temporaryDirectory, AnalysisEnvironment.JdkToolchainState.UNSELECTED, null);
  }
}
