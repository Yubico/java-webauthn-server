package com.yubico.webauthn.data;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.yubico.webauthn.exception.Base64UrlException;
import com.yubico.webauthn.util.WebAuthnCodecs;
import java.io.IOException;
import lombok.Value;


@Value
public class AttestationObject {

    private final ByteArray bytes;

    private ObjectNode decoded;

    @JsonProperty
    private AuthenticatorData authenticatorData;

    /**
     * The ''attestation statement format'' of this attestation object.
     */
    @JsonProperty
    private final String format;

    public AttestationObject(ByteArray bytes) throws IOException, Base64UrlException {
        this.bytes = bytes;

        JsonNode decoded = WebAuthnCodecs.cbor().readTree(bytes.getBytes());
        if (decoded.isObject()) {
            this.decoded = (ObjectNode) decoded;
        } else {
            throw new IllegalArgumentException("Attestation object must be a JSON object.");
        }

        authenticatorData = parseAuthenticatorData();

        format = decoded.get("fmt").textValue();
    }

    private AuthenticatorData parseAuthenticatorData() throws IOException, Base64UrlException {
        JsonNode authData = decoded.get("authData");
        if (authData.isBinary()) {
            return new AuthenticatorData(new ByteArray(authData.binaryValue()));
        } else {
            return new AuthenticatorData(ByteArray.fromBase64Url(authData.textValue()));
        }
    }

    @JsonProperty
    public JsonNode getAttestationStatement() {
        return decoded.get("attStmt");
    }

    public ObjectNode getDecoded() {
        return (ObjectNode) WebAuthnCodecs.deepCopy(this.decoded);
    }

}
