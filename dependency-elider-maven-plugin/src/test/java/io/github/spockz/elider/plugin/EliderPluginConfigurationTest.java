/* WHY: Protects the default lifecycle boundary shared by elide and tree preparation. */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

import org.apache.maven.model.PluginExecution;
import org.apache.maven.project.MavenProject;
import org.junit.jupiter.api.Test;

/** Tests effective phase selection for an elide execution. */
final class EliderPluginConfigurationTest {
  /** Phase used to prove explicit earlier lifecycle selections remain unchanged. */
  private static final String INITIALIZE_PHASE = "initialize";

  /** Default phase that ensures compiled classes are available for analysis. */
  private static final String PROCESS_CLASSES_PHASE = "process-classes";

  /** Later binding used to verify unrelated lifecycle executions are left untouched. */
  private static final String VERIFY_PHASE = "verify";

  /** Goal configured on each execution under test. */
  private static final String ELIDE_GOAL = "elide";

  /** JUnit constructs this package-private test class reflectively. */
  @SuppressWarnings({"PMD.CommentDefaultAccessModifier", "PMD.UncommentedEmptyConstructor"})
  /* package */ EliderPluginConfigurationTest() {}

  @Test
  void omittedPhaseDefaultsToProcessClassesAndExplicitPhaseIsPreserved() throws Exception {
    final PluginExecution omitted = new PluginExecution();
    final PluginExecution explicit = new PluginExecution();
    final PluginExecution explicitProcessClasses = new PluginExecution();
    final PluginExecution explicitVerify = new PluginExecution();
    omitted.setGoals(java.util.List.of(ELIDE_GOAL));
    explicit.setGoals(java.util.List.of(ELIDE_GOAL));
    explicitProcessClasses.setGoals(java.util.List.of(ELIDE_GOAL));
    explicitVerify.setGoals(java.util.List.of(ELIDE_GOAL));
    explicit.setPhase(INITIALIZE_PHASE);
    explicitProcessClasses.setPhase(PROCESS_CLASSES_PHASE);
    explicitVerify.setPhase(VERIFY_PHASE);
    final MavenProject project = new MavenProject();

    EliderLifecycleParticipant.applyDefaultPhase(omitted, project);
    EliderLifecycleParticipant.applyDefaultPhase(explicit, project);
    EliderLifecycleParticipant.applyDefaultPhase(explicitProcessClasses, project);
    EliderLifecycleParticipant.applyDefaultPhase(explicitVerify, project);

    assertAll(
        () ->
            assertThat(EliderPluginConfiguration.effectivePhase(omitted, project))
                .isEqualTo(PROCESS_CLASSES_PHASE),
        () ->
            assertThat(EliderPluginConfiguration.effectivePhase(explicit, project))
                .isEqualTo(INITIALIZE_PHASE),
        () ->
            assertThat(EliderPluginConfiguration.effectivePhase(explicitProcessClasses, project))
                .isEqualTo(PROCESS_CLASSES_PHASE),
        () -> assertThat(omitted.getPhase()).isEqualTo(PROCESS_CLASSES_PHASE),
        () -> assertThat(omitted.getPriority()).isEqualTo(Integer.MAX_VALUE),
        () -> assertThat(explicit.getPhase()).isEqualTo(INITIALIZE_PHASE),
        () -> assertThat(explicitProcessClasses.getPhase()).isEqualTo(PROCESS_CLASSES_PHASE),
        () -> assertThat(explicitProcessClasses.getPriority()).isEqualTo(Integer.MAX_VALUE),
        () -> assertThat(explicitVerify.getPhase()).isEqualTo(VERIFY_PHASE),
        () -> assertThat(explicitVerify.getPriority()).isEqualTo(0));
  }
}
