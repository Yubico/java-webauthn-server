package com.yubico.webauthn.data;

import com.fasterxml.jackson.annotation.JsonIgnore;
import java.util.Set;

public interface ExtensionOutputs {
  /** Returns a {@link Set} of the extension IDs for which an extension output is present. */
  @JsonIgnore
  Set<String> getExtensionIds();
}
