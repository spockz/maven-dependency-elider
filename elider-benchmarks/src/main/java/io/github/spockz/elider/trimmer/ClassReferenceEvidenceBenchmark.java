// WHY: Measures ClassReferenceEvidence bitmask edge collection against the EnumSet baseline.

package io.github.spockz.elider.trimmer;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Label;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;

/** Benchmarks EnumSet vs bitmask edge collection over fixed class fixtures. */
@State(Scope.Benchmark)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MICROSECONDS)
public class ClassReferenceEvidenceBenchmark {
  /** Number of synthetic classes generated per trial. */
  private static final int CLASS_COUNT = 12;

  /** Fixed generated class fixtures invariant across production code edits. */
  private List<SampleClass> samples = List.of();

  /** Creates benchmark state with an empty sample list before JMH setup runs. */
  public ClassReferenceEvidenceBenchmark() {
    // JMH populates fixture state in @Setup.
  }

  /** Generates fixed, deterministic class fixtures once per benchmark trial. */
  @Setup
  public void setUp() {
    final List<SampleClass> generated = new ArrayList<>(CLASS_COUNT);
    for (int index = 0; index < CLASS_COUNT; index++) {
      final String name = "benchmark/fixture/RefSample" + index;
      generated.add(new SampleClass(name, generateFixtureClass(name, index)));
    }
    samples = List.copyOf(generated);
  }

  /** Measures optimized ClassReferenceEvidence.collectReferences in isolation. */
  @Benchmark
  public int optimizedCollectReferences() {
    int total = 0;
    for (final SampleClass sample : samples) {
      total += ClassReferenceEvidence.collectReferences(sample.name(), sample.bytes(), true).size();
    }
    return total;
  }

  /** Measures verbatim pre-optimization EnumSet edge collection in isolation. */
  @Benchmark
  public int baselineEnumSetCollectReferences() {
    int total = 0;
    for (final SampleClass sample : samples) {
      total +=
          BaselineClassReferenceEvidence.collectReferences(sample.name(), sample.bytes(), true)
              .size();
    }
    return total;
  }

  private static byte[] generateFixtureClass(final String internalName, final int seed) {
    final ClassWriter writer = new ClassWriter(0);
    writer.visit(
        Opcodes.V21,
        Opcodes.ACC_PUBLIC,
        internalName,
        null,
        "java/lang/Object",
        new String[] {"java/io/Serializable"});
    writer.visitField(Opcodes.ACC_PRIVATE, "items", "[[Ljava/lang/String;", null, null).visitEnd();
    writer.visitField(Opcodes.ACC_PRIVATE, "lookup", "Ljava/util/Map;", null, null).visitEnd();
    final MethodVisitor method =
        writer.visitMethod(
            Opcodes.ACC_PUBLIC,
            "transform" + seed,
            "([Ljava/lang/String;Ljava/util/List;)Ljava/util/Set;",
            null,
            null);
    method.visitCode();
    final Label start = new Label();
    final Label end = new Label();
    method.visitLabel(start);
    method.visitMethodInsn(Opcodes.INVOKESTATIC, "java/util/Set", "of", "()Ljava/util/Set;", true);
    method.visitInsn(Opcodes.ARETURN);
    method.visitLabel(end);
    method.visitLocalVariable("values", "[Ljava/lang/String;", null, start, end, 1);
    method.visitLocalVariable("extra", "Ljava/util/List;", null, start, end, 2);
    method.visitMaxs(1, 3);
    method.visitEnd();
    writer.visitEnd();
    return writer.toByteArray();
  }

  private record SampleClass(String name, byte[] bytes) {}
}
