package com.yubico.webauthn.data;

import com.fasterxml.jackson.annotation.JsonIgnore;
import java.util.Set;

public interface ExtensionInputs {

    @JsonIgnore
    Set<String> getExtensionIds();

}
