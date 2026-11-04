/* WHY: Protects normalized locator identity and retained source spellings. */

package io.github.spockz.elider.model;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.Set;
import org.junit.jupiter.api.Test;

class CodeReferenceTest {
  @Test
  void rejectsOriginalSourcePathsThatDoNotNormalizeToTheDeclaredIdentity() {
    assertThatThrownBy(
            () ->
                new CodeReference(
                    CodeReference.Kind.SOURCE_FILE, "p/Foo.java", Set.of("q/Bar.java")))
        .isInstanceOf(IllegalArgumentException.class);
  }
}
