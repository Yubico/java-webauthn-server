package com.yubico.webauthn.data;

import java.util.Optional;
import lombok.Builder;
import lombok.NonNull;
import lombok.Value;


@Value
@Builder
public class AssertionRequest {
    private ByteArray requestId;
    private Optional<String> username;
    private PublicKeyCredentialRequestOptions publicKeyCredentialRequestOptions;

    private AssertionRequest(
        @NonNull ByteArray requestId,
        @NonNull Optional<String> username,
        @NonNull PublicKeyCredentialRequestOptions publicKeyCredentialRequestOptions
    ) {
        this.requestId = requestId;
        this.username = username;
        this.publicKeyCredentialRequestOptions = publicKeyCredentialRequestOptions;
    }

}
