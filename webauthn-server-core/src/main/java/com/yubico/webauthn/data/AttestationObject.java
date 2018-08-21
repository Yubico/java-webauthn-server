package com.yubico.webauthn.data;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.yubico.webauthn.exception.Base64UrlException;
import com.yubico.webauthn.impl.util.WebAuthnCodecs;
import java.io.IOException;
import lombok.NonNull;
import lombok.Value;


@Value
public class AttestationObject {

    @JsonIgnore
    @NonNull
    private final ByteArray bytes;

    @JsonIgnore
    @NonNull
    private final ObjectNode decoded;

    @NonNull
    @JsonIgnore
    private final AuthenticatorData authenticatorData;

    @NonNull
    @JsonProperty("authData")
    private final ByteArray authData;

    /**
     * The ''attestation statement format'' of this attestation object.
     */
    @NonNull
    @JsonProperty("fmt")
    private final String format;

    public AttestationObject(@NonNull ByteArray bytes) throws IOException, Base64UrlException {
        this.bytes = bytes;

        JsonNode decoded = WebAuthnCodecs.cbor().readTree(bytes.getBytes());
        if (decoded.isObject()) {
            this.decoded = (ObjectNode) decoded;
        } else {
            throw new IllegalArgumentException("Attestation object must be a JSON object.");
        }

        JsonNode authData = decoded.get("authData");
        if (authData.isBinary()) {
            this.authData = new ByteArray(authData.binaryValue());
        } else {
            this.authData = ByteArray.fromBase64Url(authData.textValue());
        }

        authenticatorData = new AuthenticatorData(this.authData);
        format = decoded.get("fmt").textValue();
    }

    @JsonProperty("attStmt")
    public JsonNode getAttestationStatement() {
        return decoded.get("attStmt");
    }

    public ObjectNode getDecoded() {
        return (ObjectNode) WebAuthnCodecs.deepCopy(this.decoded);
    }

}
