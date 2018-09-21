package com.yubico.webauthn.data;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Optional;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.NonNull;
import lombok.Value;


@Value
@AllArgsConstructor(access = AccessLevel.PRIVATE)
@Builder
public class AssertionRequest {

    @NonNull
    private final PublicKeyCredentialRequestOptions publicKeyCredentialRequestOptions;

    @NonNull
    @Builder.Default
    private final Optional<String> username = Optional.empty();

    @JsonCreator
    private AssertionRequest(
        @NonNull @JsonProperty("publicKeyCredentialRequestOptions") PublicKeyCredentialRequestOptions publicKeyCredentialRequestOptions,
        @JsonProperty("username") String username
    ) {
        this(publicKeyCredentialRequestOptions, Optional.ofNullable(username));
    }

}
