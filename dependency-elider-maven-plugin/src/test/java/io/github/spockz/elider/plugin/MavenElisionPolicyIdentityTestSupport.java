// WHY: Supplies explicit empty-policy identity to synthetic report fixtures without production
// defaults.

package io.github.spockz.elider.plugin;

import java.util.List;

/** Provides explicit empty-policy identities for synthetic report fixtures. */
final class MavenElisionPolicyIdentityTestSupport {
  private MavenElisionPolicyIdentityTestSupport() {}

  /* package */ static MavenElisionPolicyIdentity emptyPolicy() {
    return new MavenElisionPolicyIdentity(
        List.of(), List.of(), MavenElisionGraphBinding.sha256(List.of()));
  }
}
