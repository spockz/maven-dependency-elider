/* WHY: Enforces the record size limit before encoding can allocate an oversized buffer. */

package io.github.spockz.elider.cache;

import java.io.ByteArrayOutputStream;

/** Bounded per-write buffer; codec operations own distinct instances. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class BoundedByteArrayOutputStream extends ByteArrayOutputStream {
  /** Maximum buffer size imposed by the cache record framing. */
  private final int maximum;

  /** Creates a stream that refuses writes past the configured record bound. */
  BoundedByteArrayOutputStream(final int maximum) {
    super();
    this.maximum = maximum;
  }

  @Override
  public void write(final int value) {
    ensureCapacity(1);
    super.write(value);
  }

  @Override
  public void write(final byte[] bytes, final int offset, final int length) {
    ensureCapacity(length);
    super.write(bytes, offset, length);
  }

  private void ensureCapacity(final int length) {
    if (length < 0 || count > maximum - length) {
      throw new IllegalArgumentException("Cache record exceeds maximum size");
    }
  }
}
