package com.yubico.webauthn.data;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.yubico.webauthn.data.exception.Base64UrlException;
import java.io.IOException;
import java.nio.charset.Charset;
import java.util.Optional;
import lombok.NonNull;
import lombok.Value;


@Value
public class AuthenticatorAssertionResponse implements AuthenticatorResponse {

    @NonNull
    private final ByteArray authenticatorData;

    @NonNull
    private final ByteArray clientDataJSON;

    @NonNull
    private final ByteArray signature;

    @NonNull
    private final Optional<ByteArray> userHandle;

    @NonNull
    private final transient CollectedClientData clientData;

    @JsonCreator
    public AuthenticatorAssertionResponse(
        @NonNull @JsonProperty("authenticatorData") final ByteArray authenticatorData,
        @NonNull @JsonProperty("clientDataJSON") final ByteArray clientDataJson,
        @NonNull @JsonProperty("signature") final ByteArray signature,
        @JsonProperty("userHandle") final ByteArray userHandle
    ) throws IOException, Base64UrlException {
        this.authenticatorData = authenticatorData;
        this.clientDataJSON = clientDataJson;
        this.signature = signature;
        this.userHandle = Optional.ofNullable(userHandle);
        this.clientData = new CollectedClientData(clientDataJSON);
    }

    @JsonIgnore
    public String getClientDataJSONString() {
        return new String(clientDataJSON.getBytes(), Charset.forName("UTF-8"));
    }

}
