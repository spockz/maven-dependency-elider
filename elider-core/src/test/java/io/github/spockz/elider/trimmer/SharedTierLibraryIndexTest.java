/* WHY: Verifies shared tier library indexing matches unshared per-target analysis. */

package io.github.spockz.elider.trimmer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import proguard.classfile.ClassPool;

/** Differential and concurrency tests for shared tier library indexing. */
@SuppressWarnings({
  "PMD.AtLeastOneConstructor",
  "PMD.AvoidDuplicateLiterals",
  "PMD.UnitTestContainsTooManyAsserts",
  "PMD.DoNotUseThreads",
  "PMD.AvoidCatchingGenericException"
})
final class SharedTierLibraryIndexTest {
  /** Temporary directory for test JAR fixtures. */
  @TempDir /* default */ Path tempDir;

  @Test
  void sharedTierMatchesUnsharedAnalysisAcrossAllTargetsAndPolicies() throws Exception {
    final Path jarA =
        ClosedWorldTestFixtures.writeJar(
            tempDir,
            "jar-a.jar",
            Map.of(
                "fixture/a/AppRoot",
                    classCalling(
                        "fixture/a/AppRoot",
                        "call",
                        "java/lang/Object",
                        "fixture/b/Service",
                        "serve",
                        "()V"),
                "fixture/a/UnusedA", classBytes("fixture/a/UnusedA", "java/lang/Object")));
    final Path jarB =
        ClosedWorldTestFixtures.writeJar(
            tempDir,
            "jar-b.jar",
            Map.of(
                "fixture/b/Service",
                    classCalling(
                        "fixture/b/Service",
                        "serve",
                        "fixture/c/BaseHelper",
                        "fixture/c/BodyHelper",
                        "help",
                        "()V"),
                "fixture/b/UnusedB", classBytes("fixture/b/UnusedB", "java/lang/Object")));
    final Path jarC =
        ClosedWorldTestFixtures.writeJar(
            tempDir,
            "jar-c.jar",
            Map.of(
                "fixture/c/BaseHelper", classBytes("fixture/c/BaseHelper", "java/lang/Object"),
                "fixture/c/BodyHelper",
                    classCalling(
                        "fixture/c/BodyHelper",
                        "help",
                        "java/lang/Object",
                        "java/lang/String",
                        "valueOf",
                        "(I)Ljava/lang/String;"),
                "fixture/c/UnusedC", classBytes("fixture/c/UnusedC", "java/lang/Object")));

    final ClassPool jdkTable = new JdkApiClassTableReader().read();
    final List<Path> allJars = List.of(jarA, jarB, jarC);
    final TrimAnalysisSession unsharedSession = new TrimAnalysisSession(new DependencyJarTrimmer());
    final TrimAnalysisSession sharedSession = new TrimAnalysisSession(new DependencyJarTrimmer());
    final TrimAnalysisSession.SharedTierContext sharedTier =
        sharedSession.prepareSharedTierContext(allJars, jdkTable);

    final DependencyJarTrimmer.PreparedAnalysis sharedA =
        sharedTier.prepareWithUnchangedPassThroughLibraries(
            jarA, List.of(jarB, jarC), Set.of(), false);
    final DependencyJarTrimmer.PreparedAnalysis sharedB =
        sharedTier.prepareWithUnchangedPassThroughLibraries(
            jarB, List.of(jarA, jarC), Set.of(), false);
    final DependencyJarTrimmer.PreparedAnalysis sharedC =
        sharedTier.prepareUnchangedPassThrough(jarC, List.of(jarA, jarB), Set.of());

    assertThat(sharedTier.indexBuilt())
        .as("Shared tier index should defer construction until first analyze call")
        .isFalse();

    final DependencyJarTrimmer.PreparedAnalysis unsharedA =
        unsharedSession.prepareWithUnchangedPassThroughLibraries(
            jarA, List.of(jarB, jarC), jdkTable, Set.of(), false);
    final DependencyJarTrimmer.PreparedAnalysis unsharedB =
        unsharedSession.prepareWithUnchangedPassThroughLibraries(
            jarB, List.of(jarA, jarC), jdkTable, Set.of(), false);
    final DependencyJarTrimmer.PreparedAnalysis unsharedC =
        unsharedSession.prepareUnchangedPassThrough(jarC, List.of(jarA, jarB), jdkTable, Set.of());

    final ClosureQueryPolicy closedWorld =
        ClosureQueryPolicy.closedWorld(
            Set.of("fixture.a.AppRoot", "fixture.b.Service", "fixture.c.BaseHelper"));

    assertAll(
        "Shared tier analyses must match unshared analyses",
        () ->
            assertSameAnalysis(
                "jarA conservative",
                unsharedA.analyze(Set.of("fixture.a.AppRoot")),
                sharedA.analyze(Set.of("fixture.a.AppRoot"))),
        () ->
            assertSameAnalysis(
                "jarA closed-world",
                unsharedA.analyze(Set.of("fixture.a.AppRoot"), closedWorld),
                sharedA.analyze(Set.of("fixture.a.AppRoot"), closedWorld)),
        () ->
            assertSameAnalysis(
                "jarB conservative",
                unsharedB.analyze(Set.of("fixture.b.Service")),
                sharedB.analyze(Set.of("fixture.b.Service"))),
        () ->
            assertSameAnalysis(
                "jarC pass-through",
                unsharedC.analyze(Set.of("fixture.c.BaseHelper")),
                sharedC.analyze(Set.of("fixture.c.BaseHelper"))));
    assertThat(sharedTier.indexBuilt()).isTrue();
  }

  @Test
  void sharedTierSupportsConcurrentAnalyzeAndPreservesMissingReferenceFailures() throws Exception {
    final Path jarA =
        ClosedWorldTestFixtures.writeJar(
            tempDir,
            "conc-a.jar",
            Map.of(
                "fixture/conc/RootA",
                classCalling(
                    "fixture/conc/RootA",
                    "call",
                    "java/lang/Object",
                    "fixture/conc/MissingTarget",
                    "nope",
                    "()V")));
    final Path jarB =
        ClosedWorldTestFixtures.writeJar(
            tempDir,
            "conc-b.jar",
            Map.of("fixture/conc/RootB", classBytes("fixture/conc/RootB", "java/lang/Object")));

    final ClassPool jdkTable = new JdkApiClassTableReader().read();
    final TrimAnalysisSession session = new TrimAnalysisSession(new DependencyJarTrimmer());
    final TrimAnalysisSession.SharedTierContext sharedTier =
        session.prepareSharedTierContext(List.of(jarA, jarB), jdkTable);
    final DependencyJarTrimmer.PreparedAnalysis preparedA =
        sharedTier.prepareWithUnchangedPassThroughLibraries(jarA, List.of(jarB), Set.of(), false);
    final DependencyJarTrimmer.PreparedAnalysis preparedB =
        sharedTier.prepareWithUnchangedPassThroughLibraries(jarB, List.of(jarA), Set.of(), false);

    try (ExecutorService executor = Executors.newFixedThreadPool(2)) {
      final Callable<Throwable> taskA =
          () -> {
            try {
              preparedA.analyze(Set.of("fixture.conc.RootA"));
              return null;
            } catch (final Throwable thrown) {
              return thrown;
            }
          };
      final Callable<DependencyJarTrimmer.TrimAnalysis> taskB =
          () -> preparedB.analyze(Set.of("fixture.conc.RootB"));
      final Future<Throwable> futureA = executor.submit(taskA);
      final Future<DependencyJarTrimmer.TrimAnalysis> futureB = executor.submit(taskB);
      assertThat(futureB.get().retainedClasses()).containsExactly("fixture/conc/RootB");
      assertThatThrownBy(
              () -> {
                final Throwable thrown = futureA.get();
                if (thrown != null) {
                  throw thrown;
                }
              })
          .isInstanceOf(DependencyJarTrimmer.UnresolvedReferenceException.class);
    }
  }

  private static void assertSameAnalysis(
      final String label,
      final DependencyJarTrimmer.TrimAnalysis expected,
      final DependencyJarTrimmer.TrimAnalysis actual) {
    assertAll(
        label,
        () -> assertThat(actual.totalClasses()).isEqualTo(expected.totalClasses()),
        () -> assertThat(actual.retainedClasses()).isEqualTo(expected.retainedClasses()),
        () -> assertThat(actual.roots()).isEqualTo(expected.roots()),
        () ->
            assertThat(actual.reachableLibraryClasses())
                .isEqualTo(expected.reachableLibraryClasses()));
  }

  private static byte[] classBytes(final String internalName, final String superName) {
    final ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_FRAMES);
    writer.visit(Opcodes.V21, Opcodes.ACC_PUBLIC, internalName, null, superName, null);
    final MethodVisitor init = writer.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
    init.visitCode();
    init.visitVarInsn(Opcodes.ALOAD, 0);
    init.visitMethodInsn(Opcodes.INVOKESPECIAL, superName, "<init>", "()V", false);
    init.visitInsn(Opcodes.RETURN);
    init.visitMaxs(0, 0);
    init.visitEnd();
    writer.visitEnd();
    return writer.toByteArray();
  }

  private static byte[] classCalling(
      final String internalName,
      final String declaredMethodName,
      final String superName,
      final String targetOwner,
      final String methodName,
      final String descriptor) {
    final ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_FRAMES);
    writer.visit(Opcodes.V21, Opcodes.ACC_PUBLIC, internalName, null, superName, null);
    final MethodVisitor init = writer.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
    init.visitCode();
    init.visitVarInsn(Opcodes.ALOAD, 0);
    init.visitMethodInsn(Opcodes.INVOKESPECIAL, superName, "<init>", "()V", false);
    init.visitInsn(Opcodes.RETURN);
    init.visitMaxs(0, 0);
    init.visitEnd();
    final MethodVisitor call =
        writer.visitMethod(
            Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, declaredMethodName, "()V", null, null);
    call.visitCode();
    call.visitMethodInsn(Opcodes.INVOKESTATIC, targetOwner, methodName, descriptor, false);
    call.visitInsn(Opcodes.RETURN);
    call.visitMaxs(0, 0);
    call.visitEnd();
    writer.visitEnd();
    return writer.toByteArray();
  }
}
