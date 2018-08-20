package com.yubico.webauthn.data;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.yubico.u2f.data.messages.key.util.U2fB64Encoding;
import com.yubico.u2f.exceptions.U2fBadInputException;
import com.yubico.webauthn.util.BinaryUtil;
import java.nio.charset.Charset;
import java.util.Optional;
import lombok.NonNull;
import lombok.Value;


@Value
public class AuthenticatorAssertionResponse implements AuthenticatorResponse {

    private byte[] authenticatorData;
    private byte[] clientDataJSON;
    private byte[] signature;
    private Optional<byte[]> userHandle;

    @JsonCreator
    public AuthenticatorAssertionResponse(
        @NonNull @JsonProperty("authenticatorData") String authenticatorDataBase64,
        @NonNull @JsonProperty("clientDataJSON") String clientDataJsonBase64,
        @NonNull @JsonProperty("signature") String signatureBase64,
        @JsonProperty("userHandle") String userHandleBase64
    ) throws U2fBadInputException {
        authenticatorData = U2fB64Encoding.decode(authenticatorDataBase64);
        clientDataJSON = U2fB64Encoding.decode(clientDataJsonBase64);
        signature = U2fB64Encoding.decode(signatureBase64);

        if (userHandleBase64 == null) {
            userHandle = Optional.empty();
        } else {
            userHandle = Optional.of(U2fB64Encoding.decode(userHandleBase64));
        }
    }

    public byte[] getAuthenticatorData() {
        return BinaryUtil.copy(authenticatorData);
    }

    public byte[] getClientDataJSON() {
        return BinaryUtil.copy(clientDataJSON);
    }

    public String getClientDataJSONString() {
        return new String(clientDataJSON, Charset.forName("UTF-8"));
    }

    public byte[] getSignature() {
        return BinaryUtil.copy(signature);
    }

    public Optional<byte[]> getUserHandle() {
        return userHandle.map(BinaryUtil::copy);
    }

    @JsonProperty("signature")
    public String getSignatureBase64() {
        return U2fB64Encoding.encode(signature);
    }

    @JsonProperty("userHandle")
    public String getUserHandleBase64() {
        return userHandle.map(U2fB64Encoding::encode).orElse(null);
    }

}
