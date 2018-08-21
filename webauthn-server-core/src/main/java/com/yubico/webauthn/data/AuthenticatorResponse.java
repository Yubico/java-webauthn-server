package com.yubico.webauthn.data;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import com.yubico.webauthn.exception.Base64UrlException;
import com.yubico.webauthn.impl.util.WebAuthnCodecs;
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
     * The `clientData` parsed as a domain object.
     */
    @JsonIgnore
    default CollectedClientData getClientData() throws IOException, Base64UrlException {
        JsonNode clientData = WebAuthnCodecs.json().readTree(new ByteArrayInputStream(getClientDataJSON().getBytes()));
        return new CollectedClientData(clientData);
    }

}
