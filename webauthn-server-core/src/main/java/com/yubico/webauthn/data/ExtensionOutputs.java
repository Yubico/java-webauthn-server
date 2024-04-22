package com.yubico.webauthn.data;

import com.fasterxml.jackson.annotation.JsonIgnore;
import java.util.Set;

public interface ExtensionOutputs {
  /**
   * Returns a {@link Set} of recognized extension IDs for which an extension output is present.
   *
   * <p>This only includes extension identifiers recognized by the java-webauthn-server library.
   * Recognized extensions can be found as the properties of {@link
   * ClientRegistrationExtensionOutputs} for registration ceremonies, and {@link
   * ClientAssertionExtensionOutputs} for authentication ceremonies. Unknown extension identifiers
   * are silently ignored.
   */
  @JsonIgnore
  Set<String> getExtensionIds();
}
