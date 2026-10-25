// WHY: Pins the safety boundary that prevents unproven Maven lifecycle mutation.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.lang.reflect.Field;
import org.apache.maven.plugin.MojoFailureException;
import org.junit.jupiter.api.Test;

/** Verifies the explicit pre-mutation failure boundary. */
@SuppressWarnings("PMD.AvoidAccessibilityAlteration")
final class ElideMojoTest {
  /** Creates the focused test fixture. */
  @SuppressWarnings({"PMD.UncommentedEmptyConstructor", "PMD.CommentDefaultAccessModifier"})
  ElideMojoTest() {}

  @Test
  void failsBeforeAnyProjectStateIsNeededUntilLifecycleMutationIsProven() {
    assertThatThrownBy(() -> new ElideMojo().execute())
        .isInstanceOf(MojoFailureException.class)
        .hasMessageContaining("INITIALIZE artifact mutation has not been verified")
        .hasMessageContaining("analyze goal");
  }

  @Test
  void skipReturnsWithoutLoggingOrAccessingProjectState() throws ReflectiveOperationException {
    final ElideMojo mojo = new ElideMojo();
    final Field skip = ElideMojo.class.getDeclaredField("skip");
    skip.setAccessible(true);
    skip.setBoolean(mojo, true);

    assertThatCode(mojo::execute).doesNotThrowAnyException();
  }
}
