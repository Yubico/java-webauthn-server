package com.yubico.webauthn.data;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import com.yubico.webauthn.exception.Base64UrlException;
import com.yubico.webauthn.util.WebAuthnCodecs;
import java.io.ByteArrayInputStream;
import java.io.IOException;

public interface AuthenticatorResponse {

    @JsonProperty("authenticatorData")
    ByteArray getAuthenticatorData();

    @JsonProperty("_authenticatorData")
    default AuthenticatorData getParsedAuthenticatorData() {
        return new AuthenticatorData(getAuthenticatorData());
    }

    @JsonProperty("clientDataJSON")
    ByteArray getClientDataJSON();

    /**
     * The [clientDataJSON] parsed as a [[JsonNode]].
     */
    @JsonProperty("_clientData")
    default JsonNode getClientData() throws IOException {
        return WebAuthnCodecs.json().readTree(new ByteArrayInputStream(getClientDataJSON().getBytes()));
    }

    /**
     * The `clientData` parsed as a domain object.
     */
    @JsonIgnore
    default CollectedClientData getCollectedClientData() throws IOException, Base64UrlException {
        return new CollectedClientData(getClientData());
    }

}
