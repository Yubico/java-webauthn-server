package com.yubico.webauthn.data;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;
import java.util.HashSet;
import java.util.Set;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Value;
import lombok.extern.slf4j.Slf4j;

import static com.yubico.internal.util.ExceptionUtil.assure;

@Value
@AllArgsConstructor(access = AccessLevel.PRIVATE)
@Builder
@Slf4j
public final class AuthenticatorExtensionOutputs {

    static AuthenticatorExtensionOutputs parse(CBORObject cborObject) {
        assure(
            cborObject.getType() == CBORType.Map,
            "Authenticator extensions must be a CBOR map, was: %s",
            cborObject.getType()
        );

        AuthenticatorExtensionOutputsBuilder builder = builder();

        return builder.build();
    }

    @JsonIgnore
    public Set<String> getExtensionIds() {
        Set<String> ids = new HashSet<>();
        return ids;
    }

    static AuthenticatorExtensionOutputsBuilder builder() {
        return new AuthenticatorExtensionOutputsBuilder();
    }

    static class AuthenticatorExtensionOutputsBuilder {
    }
}
