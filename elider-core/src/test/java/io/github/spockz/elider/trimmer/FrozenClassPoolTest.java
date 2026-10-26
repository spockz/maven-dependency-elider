/* WHY: Verifies graph-local hash lookups preserve ProGuard pool semantics after freezing. */

package io.github.spockz.elider.trimmer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import proguard.classfile.ClassPool;
import proguard.classfile.Clazz;
import proguard.classfile.LibraryClass;

/** Covers frozen graph pool lookup, iteration, identity, and immutable membership. */
@SuppressWarnings({"PMD.AtLeastOneConstructor", "PMD.UnitTestContainsTooManyAsserts"})
class FrozenClassPoolTest {
  @Test
  @DisplayName("ADR-0003: frozen lookup preserves sorted membership and class identities")
  void frozenLookupPreservesPoolMembershipAndIdentity() {
    final ClassPool source = new ClassPool();
    final Clazz zulu = new LibraryClass(0, "fixture/Zulu", null);
    final Clazz alpha = new LibraryClass(0, "fixture/Alpha", null);
    source.addClass(zulu);
    source.addClass(alpha);

    final FrozenClassPool frozen = FrozenClassPool.copyOf(source);

    assertThat(frozen.getClass("fixture/Zulu")).isSameAs(zulu);
    assertThat(frozen.getClass("fixture/Alpha")).isSameAs(alpha);
    assertThat(frozen.contains(zulu)).isTrue();
    assertThat(frozen.contains(alpha)).isTrue();
    assertThat(frozen.size()).isEqualTo(source.size());
    assertThat(names(frozen)).containsExactlyElementsOf(names(source));
    assertThat(classes(frozen)).containsExactlyElementsOf(classes(source));
  }

  @Test
  @DisplayName("ADR-0003: frozen lookup rejects pool membership mutation")
  void frozenLookupRejectsMembershipMutation() {
    final Clazz original = new LibraryClass(0, "fixture/Original", null);
    final Clazz added = new LibraryClass(0, "fixture/Added", null);
    final FrozenClassPool frozen = FrozenClassPool.copyOf(new ClassPool(original));

    assertThatThrownBy(() -> frozen.addClass(added))
        .isInstanceOf(IllegalStateException.class)
        .hasMessage("Cannot change frozen graph class-pool membership");
    assertThatThrownBy(() -> frozen.addClass("fixture/Alias", added))
        .isInstanceOf(IllegalStateException.class);
    assertThatThrownBy(() -> frozen.removeClass(original))
        .isInstanceOf(IllegalStateException.class);
    assertThatThrownBy(() -> frozen.removeClass("fixture/Original"))
        .isInstanceOf(IllegalStateException.class);
    assertThatThrownBy(frozen::clear).isInstanceOf(IllegalStateException.class);

    assertThat(frozen.size()).isEqualTo(1);
    assertThat(frozen.getClass("fixture/Original")).isSameAs(original);
    assertThat(frozen.getClass("fixture/Added")).isNull();
  }

  private static List<String> names(final ClassPool pool) {
    final List<String> names = new ArrayList<>();
    pool.classNames().forEachRemaining(names::add);
    return names;
  }

  private static List<Clazz> classes(final ClassPool pool) {
    final List<Clazz> classes = new ArrayList<>();
    pool.classes().forEach(classes::add);
    return classes;
  }
}
