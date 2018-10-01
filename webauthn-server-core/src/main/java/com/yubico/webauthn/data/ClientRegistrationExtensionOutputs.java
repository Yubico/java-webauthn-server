package com.yubico.webauthn.data;

import java.util.Collections;
import java.util.Set;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Value;

@Value
@AllArgsConstructor(access = AccessLevel.PRIVATE)
@Builder
public class ClientRegistrationExtensionOutputs implements ClientExtensionOutputs {

    @Override
    public Set<String> getExtensionIds() {
        return Collections.emptySet();
    }

}
