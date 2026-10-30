/* WHY: Keeps schema dispatch based on explicit kinds rather than incidental filenames. */

package io.github.spockz.elider.plugin;

import com.fasterxml.jackson.databind.JsonNode;
import java.io.IOException;
import java.util.Set;

/** Sends parsed documents to their descriptor-specific validators. */
final class NativeImageClassConfigDispatcher {
  private NativeImageClassConfigDispatcher() {}

  /* package */
  static boolean dispatch(
      final JsonNode document, final NativeImageInput input, final Set<String> roots)
      throws IOException {
    return dispatch(document, input, roots, null);
  }

  /* package */ static boolean dispatch(
      final JsonNode document,
      final NativeImageInput input,
      final Set<String> roots,
      final NativeImagePolicyRoots.ResourcePatterns selections)
      throws IOException {
    if (dispatchReflectionOrSerialization(document, input, roots)) {
      return false;
    }
    if (input.kind() == NativeImageDescriptorKind.REACHABILITY_METADATA) {
      return NativeImageUnifiedConfig.read(
          document, input.name(), roots, selections, input.selectionIdentity());
    }
    if (dispatchCore(document, input, roots) || dispatchSupplemental(document, input, roots)) {
      return false;
    }
    throw new IOException("Unsupported native-image class descriptor kind: " + input.name());
  }

  private static boolean dispatchReflectionOrSerialization(
      final JsonNode document, final NativeImageInput input, final Set<String> roots)
      throws IOException {
    return switch (input.kind()) {
      case REFLECTION, PROXY -> {
        NativeImageReflectionConfig.read(document, input.name(), input.kind(), roots);
        yield true;
      }
      case SERIALIZATION -> {
        readSerialization(document, input.name(), roots);
        yield true;
      }
      default -> false;
    };
  }

  private static void readSerialization(
      final JsonNode document, final String name, final Set<String> roots) throws IOException {
    if (document.isArray()) {
      for (final JsonNode element : document) {
        NativeImageSerializationConfig.readLegacy(element, name, roots);
      }
    } else {
      NativeImageSerializationConfig.readDocument(document, name, roots);
    }
  }

  private static boolean dispatchCore(
      final JsonNode document, final NativeImageInput input, final Set<String> roots)
      throws IOException {
    return switch (input.kind()) {
      case PREDEFINED_CLASSES -> {
        NativeImagePredefinedConfig.read(document, input, roots);
        yield true;
      }
      case SERIALIZATION_DENY -> {
        NativeImageSerializationDenyConfig.read(document, input.name());
        yield true;
      }
      default -> false;
    };
  }

  private static boolean dispatchSupplemental(
      final JsonNode document, final NativeImageInput input, final Set<String> roots)
      throws IOException {
    return switch (input.kind()) {
      case OBJECT_INLINING -> {
        NativeImageObjectInliningConfig.read(document, input.name(), roots);
        yield true;
      }
      case FOREIGN -> {
        NativeImageStandaloneSupplementalConfig.readForeign(document, input.name());
        yield true;
      }
      default -> false;
    };
  }
}
