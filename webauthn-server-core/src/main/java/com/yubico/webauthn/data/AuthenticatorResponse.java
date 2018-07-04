package com.yubico.webauthn.data;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import com.yubico.u2f.data.messages.key.util.U2fB64Encoding;
import com.yubico.u2f.exceptions.U2fBadInputException;
import com.yubico.webauthn.util.WebAuthnCodecs;
import java.io.ByteArrayInputStream;
import java.io.IOException;

public interface AuthenticatorResponse {

    byte[] getAuthenticatorData();

    @JsonProperty("authenticatorData")
    default String getAuthenticatorDataBase64() {
        return U2fB64Encoding.encode(getAuthenticatorData());
    }

    @JsonProperty("_authenticatorData")
    default AuthenticatorData getParsedAuthenticatorData() {
        return new AuthenticatorData(getAuthenticatorData());
    }

    byte[] getClientDataJSON();

    /**
     * The [clientDataJSON] parsed as a [[JsonNode]].
     */
    @JsonProperty("_clientData")
    default JsonNode getClientData() throws IOException {
        return WebAuthnCodecs.json().readTree(new ByteArrayInputStream(getClientDataJSON()));
    }

    /**
     * The `clientData` parsed as a domain object.
     */
    @JsonIgnore
    default CollectedClientData getCollectedClientData() throws IOException, U2fBadInputException {
        return new CollectedClientData(getClientData());
    }

    @JsonProperty("clientDataJSON")
    default String clientDataJSONBase64() {
        return U2fB64Encoding.encode(getClientDataJSON());
    }

}
