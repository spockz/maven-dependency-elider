/* WHY: Marks a test source so the fixture processor can generate test bytecode. */
package io.github.spockz.elider.fixture.testview;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Retention(RetentionPolicy.SOURCE)
@Target(ElementType.TYPE)
public @interface GenerateTestCase {}
