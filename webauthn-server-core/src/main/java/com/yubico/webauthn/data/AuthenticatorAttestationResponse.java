package com.yubico.webauthn.data;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.yubico.webauthn.exception.Base64UrlException;
import java.io.IOException;
import lombok.Value;


@Value
public class AuthenticatorAttestationResponse implements AuthenticatorResponse {

    private ByteArray attestationObject;

    private ByteArray clientDataJSON;

    @JsonProperty("_attestationObject")
    private final AttestationObject attestation;

    @Override
    public ByteArray getAuthenticatorData() {
        return attestation.getAuthenticatorData().getBytes();
    }

    @JsonCreator
    public AuthenticatorAttestationResponse(
        @JsonProperty("attestationObject") ByteArray attestationObject,
        @JsonProperty("clientDataJSON") ByteArray clientDataJSON
    ) throws IOException, Base64UrlException {
        this.attestationObject = attestationObject;
        this.clientDataJSON = clientDataJSON;

        attestation = new AttestationObject(attestationObject);
    }

}
