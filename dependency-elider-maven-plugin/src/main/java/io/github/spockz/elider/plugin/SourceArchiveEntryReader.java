// WHY: Streams ZIP entries through a digest so unrelated archive payloads stay out of memory.

package io.github.spockz.elider.plugin;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Optional;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

/** Reads a bounded entry and retains bytes only when source compilation needs them. */
final class SourceArchiveEntryReader {
  /** Throughput bound for streaming one decompressed archive entry. */
  private static final int BUFFER_SIZE = 8192;

  /** Per-entry limit prevents a compressed archive member exhausting memory or disk. */
  private static final long MAX_ENTRY_BYTES = 64L * 1024 * 1024;

  private SourceArchiveEntryReader() {}

  /* default */ static Content read(
      final JarFile jar, final JarEntry entry, final boolean retainBytes) throws IOException {
    final MessageDigest digest = newDigest();
    final Optional<ByteArrayOutputStream> retained =
        retainBytes ? Optional.of(new ByteArrayOutputStream()) : Optional.empty();
    final byte[] buffer = new byte[BUFFER_SIZE];
    long size = 0;
    try (InputStream input = jar.getInputStream(entry)) {
      while (true) {
        final int count = input.read(buffer);
        if (count < 0) {
          break;
        }
        if (count == 0) {
          continue;
        }
        size += count;
        requireBound(entry, size);
        digest.update(buffer, 0, count);
        retained.ifPresent(value -> value.write(buffer, 0, count));
      }
    }
    return new Content(
        HexFormat.of().formatHex(digest.digest()),
        retained.map(ByteArrayOutputStream::toByteArray),
        size);
  }

  private static MessageDigest newDigest() {
    try {
      return MessageDigest.getInstance("SHA-256");
    } catch (final NoSuchAlgorithmException exception) {
      throw new IllegalStateException("SHA-256 is unavailable", exception);
    }
  }

  private static void requireBound(final JarEntry entry, final long size) throws IOException {
    if (size > MAX_ENTRY_BYTES) {
      throw new IOException("Archive entry exceeds the supported size: " + entry.getName());
    }
  }

  /* default */ record Content(String sha256, Optional<byte[]> bytes, long size) {
    Content {
      bytes = bytes.map(byte[]::clone);
    }

    @Override
    public Optional<byte[]> bytes() {
      return bytes.map(byte[]::clone);
    }
  }
}
