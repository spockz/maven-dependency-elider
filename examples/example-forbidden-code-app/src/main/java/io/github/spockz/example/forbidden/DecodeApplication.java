// WHY: Gives the runtime policy a benign public decoder call without changing the JAR operation.

package io.github.spockz.example.forbidden;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

/** Runs the safe Commons Compress operation with a decoded value. */
public final class DecodeApplication {
  private DecodeApplication() {}

  /** Decodes a fixed Base64 representation of hello. */
  public static void main(final String[] args) {
    final byte[] encoded = "aGVsbG8=".getBytes(StandardCharsets.US_ASCII);
    final byte[] decoded = Base64.getDecoder().decode(encoded);
    System.out.println(
        ArchiveExample.entry().getName() + ": " + new String(decoded, StandardCharsets.US_ASCII));
  }
}
