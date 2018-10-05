package com.yubico.webauthn.data;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.yubico.webauthn.data.exception.Base64UrlException;
import java.io.IOException;
import lombok.NonNull;
import lombok.Value;


@Value
public class AuthenticatorAttestationResponse implements AuthenticatorResponse {

    @NonNull
    private final ByteArray attestationObject;

    @NonNull
    private final ByteArray clientDataJSON;

    @NonNull
    @JsonIgnore
    private final transient AttestationObject attestation;

    @NonNull
    @JsonIgnore
    private final transient CollectedClientData clientData;

    @Override
    @JsonIgnore
    public ByteArray getAuthenticatorData() {
        return attestation.getAuthenticatorData().getBytes();
    }

    @JsonCreator
    public AuthenticatorAttestationResponse(
        @NonNull @JsonProperty("attestationObject") ByteArray attestationObject,
        @NonNull @JsonProperty("clientDataJSON") ByteArray clientDataJSON
    ) throws IOException, Base64UrlException {
        this.attestationObject = attestationObject;
        this.clientDataJSON = clientDataJSON;

        attestation = new AttestationObject(attestationObject);
        this.clientData = new CollectedClientData(clientDataJSON);
    }

}
