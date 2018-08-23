package com.yubico.webauthn.data;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.yubico.u2f.data.messages.key.util.U2fB64Encoding;
import com.yubico.u2f.exceptions.U2fBadInputException;
import java.io.IOException;
import lombok.Value;


@Value
public class AuthenticatorAttestationResponse implements AuthenticatorResponse {

    @JsonIgnore
    private byte[] attestationObject;

    @JsonIgnore
    private byte[] clientDataJSON;

    @JsonProperty("_attestationObject")
    private final AttestationObject attestation;

    @Override
    public byte[] getAuthenticatorData() {
        return attestation.getAuthenticatorData().getBytes();
    }

    @JsonCreator
    public AuthenticatorAttestationResponse(
        @JsonProperty("attestationObject") String attestationObjectBase64,
        @JsonProperty("clientDataJSON") String clientDataJsonBase64
    ) throws U2fBadInputException, IOException {
        attestationObject = U2fB64Encoding.decode(attestationObjectBase64);
        clientDataJSON = U2fB64Encoding.decode(clientDataJsonBase64);

        attestation = new AttestationObject(attestationObject);
    }

    @JsonProperty("attestationObject")
    public String getAttestationObjectBase64() {
        return U2fB64Encoding.encode(attestationObject);
    }

    @JsonProperty("clientDataJSON")
    public String getClientDataJSONBase64() {
        return U2fB64Encoding.encode(clientDataJSON);
    }

}
