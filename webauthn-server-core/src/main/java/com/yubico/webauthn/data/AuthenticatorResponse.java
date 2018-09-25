package com.yubico.webauthn.data;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;

public interface AuthenticatorResponse {

    ByteArray getAuthenticatorData();

    @JsonIgnore
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
