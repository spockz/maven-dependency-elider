/* WHY: Generates a JUnit test that links a dependency class removed from production. */
package io.github.spockz.elider.fixture.testview;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.io.Writer;
import java.util.Set;
import javax.annotation.processing.AbstractProcessor;
import javax.annotation.processing.RoundEnvironment;
import javax.annotation.processing.SupportedAnnotationTypes;
import javax.annotation.processing.SupportedSourceVersion;
import javax.lang.model.SourceVersion;
import javax.lang.model.element.TypeElement;

@SupportedAnnotationTypes("io.github.spockz.elider.fixture.testview.GenerateTestCase")
@SupportedSourceVersion(SourceVersion.RELEASE_21)
public final class GenerateTestCaseProcessor extends AbstractProcessor {
  @Override
  public boolean process(
      final Set<? extends TypeElement> annotations, final RoundEnvironment roundEnvironment) {
    if (annotations.isEmpty() || roundEnvironment.processingOver()) {
      return false;
    }
    try (Writer source =
        processingEnv.getFiler().createSourceFile("app.GeneratedProcessorTest").openWriter()) {
      source.write(
          """
              package app;
              import static org.junit.jupiter.api.Assertions.assertEquals;
              import io.github.spockz.elider.fixture.testview.Builder;
              import org.junit.jupiter.api.Test;
              public final class GeneratedProcessorTest {
                @Test public void usesGeneratedTestDependency() {
                  assertEquals("helper", new Builder().build());
                }
              }
              """);
    } catch (final IOException failure) {
      throw new UncheckedIOException(failure);
    }
    return true;
  }
}
