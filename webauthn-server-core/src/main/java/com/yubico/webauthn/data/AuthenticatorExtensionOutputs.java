package com.yubico.webauthn.data;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;
import java.util.HashSet;
import java.util.Optional;
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

    private final RecoveryExtensionOutput recovery;

    static AuthenticatorExtensionOutputs parse(CBORObject cborObject) {
        assure(
            cborObject.getType() == CBORType.Map,
            "Authenticator extensions must be a CBOR map, was: %s",
            cborObject.getType()
        );

        AuthenticatorExtensionOutputsBuilder builder = builder();

        Optional.ofNullable(cborObject.get("recovery"))
            .flatMap(RecoveryExtensionOutput::parse)
            .ifPresent(builder::recovery);

        return builder.build();
    }

    @JsonIgnore
    public Set<String> getExtensionIds() {
        Set<String> ids = new HashSet<>();

        getRecovery().ifPresent(recovery -> ids.add("recovery"));

        return ids;
    }

    @JsonProperty("recovery")
    public Optional<RecoveryExtensionOutput> getRecovery() {
        return Optional.ofNullable(recovery);
    }

    static AuthenticatorExtensionOutputsBuilder builder() {
        return new AuthenticatorExtensionOutputsBuilder();
    }

    static class AuthenticatorExtensionOutputsBuilder {
    }
}
