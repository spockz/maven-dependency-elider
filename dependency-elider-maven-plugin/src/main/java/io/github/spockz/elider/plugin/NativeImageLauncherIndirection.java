/* WHY: Isolates Graal launcher inputs whose classes are hidden outside modeled metadata. */

package io.github.spockz.elider.plugin;

import java.io.IOException;
import java.util.List;

/** Rejects audited classpath, launch, and dynamic-component indirections. */
final class NativeImageLauncherIndirection {
  /** Options whose separate or attached values select unmodeled launch inputs. */
  private static final List<String> OPTIONS =
      List.of(
          "-cp",
          "-classpath",
          "--class-path",
          "-p",
          "--module-path",
          "--add-modules",
          "--limit-modules",
          "-jar",
          "-m",
          "--module",
          "--configurations-path",
          "--exclude-config",
          "--bundle-apply");

  private NativeImageLauncherIndirection() {}

  /* package */ static void validate(final String argument) throws IOException {
    validateArgfile(argument);
    validateOperand(argument);
    validateOption(argument);
    validateDynamicComponent(argument);
    validateForwardedJvmArgument(argument);
  }

  private static void validateArgfile(final String argument) throws IOException {
    if (argument.startsWith("@")) {
      NativeImageIndirectionGuard.reject(argument, "argument files are unsupported");
    }
  }

  private static void validateOperand(final String argument) throws IOException {
    if (!argument.startsWith("-")) {
      NativeImageIndirectionGuard.reject(
          argument, "positional main-class and image operands are unsupported");
    }
  }

  private static void validateOption(final String argument) throws IOException {
    for (final String option : OPTIONS) {
      if (isOptionForm(argument, option)) {
        NativeImageIndirectionGuard.reject(
            argument, "launcher indirection '" + option + "' is unsupported");
      }
    }
  }

  private static void validateDynamicComponent(final String argument) throws IOException {
    if (argument.startsWith("--language:")
        || argument.startsWith("--tool:")
        || argument.startsWith("--macro:")) {
      NativeImageIndirectionGuard.reject(
          argument, "dynamic language, tool, and macro selection is unsupported");
    }
  }

  private static void validateForwardedJvmArgument(final String argument) throws IOException {
    if (!argument.startsWith("-J") || argument.length() <= 2) {
      return;
    }
    final String nested = argument.substring(2);
    if (nested.startsWith("@")) {
      NativeImageIndirectionGuard.reject(argument, "forwarded JVM argument files are unsupported");
    }
    if (nested.startsWith("-javaagent:")
        || nested.startsWith("-agentlib:")
        || nested.startsWith("-agentpath:")) {
      NativeImageIndirectionGuard.reject(argument, "forwarded JVM agents are unsupported");
    }
    for (final String option : OPTIONS) {
      if (isOptionForm(nested, option)) {
        NativeImageIndirectionGuard.reject(
            argument, "forwarded launcher indirection '" + option + "' is unsupported");
      }
    }
  }

  private static boolean isOptionForm(final String argument, final String option) {
    return argument.equals(option) || argument.startsWith(option + "=");
  }
}
