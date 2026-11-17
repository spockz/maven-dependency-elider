// WHY: Measures ClassFileAttributeInventory byte-cursor parsing against DataInputStream baseline.

package io.github.spockz.elider.trimmer;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import org.objectweb.asm.Attribute;
import org.objectweb.asm.ByteVector;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Label;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.RecordComponentVisitor;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;

/** Benchmarks DataInputStream vs byte-cursor attribute inventory. */
@State(Scope.Benchmark)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MICROSECONDS)
public class ClassFileAttributeInventoryBenchmark {
  /** Number of synthetic classes generated per trial. */
  private static final int CLASS_COUNT = 12;

  /** Fixed generated class fixtures invariant across production code edits. */
  private List<byte[]> samples = List.of();

  /** Creates benchmark state with an empty sample list before JMH setup runs. */
  public ClassFileAttributeInventoryBenchmark() {
    // JMH populates fixture state in @Setup.
  }

  /** Generates fixed, deterministic class fixtures once per benchmark trial. */
  @Setup
  public void setUp() {
    final List<byte[]> generated = new ArrayList<>(CLASS_COUNT);
    for (int index = 0; index < CLASS_COUNT; index++) {
      generated.add(generateFixtureClass(index));
    }
    samples = List.copyOf(generated);
  }

  /** Measures optimized ClassFileAttributeInventory.unrecognizedAttributes. */
  @Benchmark
  public int optimizedUnrecognizedAttributes() throws IOException {
    int total = 0;
    for (final byte[] bytes : samples) {
      total += ClassFileAttributeInventory.unrecognizedAttributes(bytes).size();
    }
    return total;
  }

  /** Measures verbatim pre-optimization DataInputStream implementation. */
  @Benchmark
  public int baselineDataInputStream() throws IOException {
    int total = 0;
    for (final byte[] bytes : samples) {
      total += BaselineClassFileAttributeInventory.unrecognizedAttributes(bytes).size();
    }
    return total;
  }

  private static byte[] generateFixtureClass(final int seed) {
    final boolean isRecord = (seed & 1) == 0;
    final ClassWriter writer = new ClassWriter(0);
    writer.visit(
        Opcodes.V21,
        Opcodes.ACC_PUBLIC | (isRecord ? Opcodes.ACC_RECORD : 0),
        "benchmark/fixture/AttrSample" + seed,
        null,
        isRecord ? "java/lang/Record" : "java/lang/Object",
        null);
    if (isRecord) {
      final RecordComponentVisitor component = writer.visitRecordComponent("value", "I", null);
      component.visitEnd();
    }
    writer.visitAttribute(new CustomAttribute("CustomAttr" + seed));
    final MethodVisitor method = writer.visitMethod(Opcodes.ACC_PUBLIC, "run", "()V", null, null);
    method.visitCode();
    final Label start = new Label();
    final Label end = new Label();
    method.visitLabel(start);
    method.visitLineNumber(10, start);
    method.visitInsn(Opcodes.RETURN);
    method.visitLabel(end);
    method.visitLocalVariable(
        "this", "Lbenchmark/fixture/AttrSample" + seed + ";", null, start, end, 0);
    method.visitMaxs(0, 1);
    method.visitEnd();
    writer.visitEnd();
    return writer.toByteArray();
  }

  /** Synthetic custom attribute to exercise non-standard attribute handling. */
  private static final class CustomAttribute extends Attribute {
    private CustomAttribute(final String type) {
      super(type);
    }

    @Override
    protected ByteVector write(
        final ClassWriter classWriter,
        final byte[] code,
        final int codeLength,
        final int maxStack,
        final int maxLocals) {
      return new ByteVector(4).putInt(1);
    }
  }
}
