/* WHY: Provides a runnable consumer fixture whose JSON output proves Jackson remains
 * usable after dependency elision.
 */

package io.github.spockz.example.basic;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.Map;

/** Provides the executable entry point for the basic reference fixture. */
public final class BasicApplication {

  private BasicApplication() {}

  /** Emits {@code {"message":"hello"}} using Jackson. */
  @SuppressWarnings("PMD.SystemPrintln")
  public static void main(String[] args) throws JsonProcessingException {
    System.out.println(new ObjectMapper().writeValueAsString(Map.of("message", "hello")));
  }
}
