package com.yubico.webauthn.data;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.yubico.u2f.data.messages.key.util.U2fB64Encoding;
import com.yubico.u2f.exceptions.U2fBadInputException;
import com.yubico.webauthn.util.BinaryUtil;
import com.yubico.webauthn.util.WebAuthnCodecs;
import java.io.IOException;
import lombok.Value;


@Value
public class AttestationObject {

    private final byte[] bytes;

    private ObjectNode decoded;

    @JsonProperty
    private AuthenticatorData authenticatorData;

    /**
     * The ''attestation statement format'' of this attestation object.
     */
    @JsonProperty
    private final String format;

    public AttestationObject(byte[] bytes) throws IOException, U2fBadInputException {
        this.bytes = BinaryUtil.copy(bytes);

        JsonNode decoded = WebAuthnCodecs.cbor().readTree(bytes);
        if (decoded.isObject()) {
            this.decoded = (ObjectNode) decoded;
        } else {
            throw new IllegalArgumentException("Attestation object must be a JSON object.");
        }

        authenticatorData = parseAuthenticatorData();

        format = decoded.get("fmt").textValue();
    }

    private AuthenticatorData parseAuthenticatorData() throws IOException, U2fBadInputException {
        JsonNode authData = decoded.get("authData");
        if (authData.isBinary())
          return new AuthenticatorData(authData.binaryValue());
        else
          return new AuthenticatorData(U2fB64Encoding.decode(authData.textValue()));
    }

    public byte[] getBytes() {
        return BinaryUtil.copy(this.bytes);
    }

    @JsonProperty
    public JsonNode getAttestationStatement() {
        return decoded.get("attStmt");
    }

    public ObjectNode getDecoded() {
        return (ObjectNode) WebAuthnCodecs.deepCopy(this.decoded);
    }

}
