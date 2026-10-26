/* WHY: Keeps signature-polymorphic call-site tests separate from general archive closure tests. */

package io.github.spockz.elider.trimmer;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** JUnit fixtures verify invalid signature-polymorphic references fail closed. */
@SuppressWarnings({"PMD.CommentDefaultAccessModifier", "PMD.AtLeastOneConstructor"})
class SignaturePolymorphicNegativeTest {
  /** Candidate root class used by negative reference fixtures. */
  private static final String MISSING_METHOD_ROOT = "fixture.MissingMethod";

  /** The default access modifier allows JUnit to inject this temporary directory. */
  @TempDir Path temporaryDirectory;

  @Test
  @DisplayName("ADR-0003: unrelated missing members remain fatal")
  void unrelatedMissingMethodCallStillFailsClosed() throws Exception {
    final Path candidateJar =
        SignaturePolymorphicTestSupport.writeMissingMemberCallJar(
            temporaryDirectory,
            "missing-method.jar",
            "java/lang/String",
            "missing",
            "()Ljava/lang/Object;");
    assertThatThrownBy(
            () ->
                SignaturePolymorphicTestSupport.analyze(candidateJar, List.of(MISSING_METHOD_ROOT)))
        .isInstanceOf(DependencyJarTrimmer.UnresolvedReferenceException.class)
        .hasMessageContaining("java/lang/String.missing()Ljava/lang/Object;");
  }

  @Test
  @DisplayName("ADR-0003: MethodHandle names alone do not authorize missing-member tolerance")
  void bogusSignaturePolymorphicNameStillFailsClosed() throws Exception {
    final Path candidateJar =
        SignaturePolymorphicTestSupport.writeMissingMemberCallJar(
            temporaryDirectory,
            "bogus-method-handle.jar",
            "java/lang/invoke/MethodHandle",
            "invokeCustom",
            "()Ljava/lang/Object;");

    assertThatThrownBy(
            () ->
                SignaturePolymorphicTestSupport.analyze(candidateJar, List.of(MISSING_METHOD_ROOT)))
        .isInstanceOf(DependencyJarTrimmer.UnresolvedReferenceException.class)
        .hasMessageContaining("java/lang/invoke/MethodHandle.invokeCustom");
  }

  @Test
  @DisplayName("ADR-0003: unresolved custom call-site types remain fatal")
  void missingMethodHandleCallSiteTypeStillFailsClosed() throws Exception {
    final Path candidateJar =
        SignaturePolymorphicTestSupport.writeMissingMemberCallJar(
            temporaryDirectory,
            "missing-method-handle-type.jar",
            "java/lang/invoke/MethodHandle",
            "invokeExact",
            "(Lfixture/Ghost;)Ljava/lang/Object;");

    assertThatThrownBy(
            () ->
                SignaturePolymorphicTestSupport.analyze(candidateJar, List.of(MISSING_METHOD_ROOT)))
        .isInstanceOf(DependencyJarTrimmer.UnresolvedReferenceException.class)
        .hasMessageContaining("fixture/Ghost");
  }

  @Test
  @DisplayName("ADR-0003: signature-polymorphic name on an ordinary owner stays strict")
  void ordinaryOwnerNamedInvokeExactStillFailsClosed() throws Exception {
    final Path candidateJar =
        SignaturePolymorphicTestSupport.writeMissingMemberCallJar(
            temporaryDirectory,
            "ordinary-owner-invoke-exact.jar",
            "java/lang/String",
            "invokeExact",
            "(Ljava/lang/Object;)Ljava/lang/Object;");

    assertThatThrownBy(
            () ->
                SignaturePolymorphicTestSupport.analyze(candidateJar, List.of(MISSING_METHOD_ROOT)))
        .isInstanceOf(DependencyJarTrimmer.UnresolvedReferenceException.class)
        .hasMessageContaining("java/lang/String.invokeExact");
  }
}
