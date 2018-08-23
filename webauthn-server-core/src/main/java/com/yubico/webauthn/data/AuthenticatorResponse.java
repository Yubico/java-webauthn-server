package com.yubico.webauthn.data;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.yubico.util.ByteArray;

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
    CollectedClientData getClientData();

}
