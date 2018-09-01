package com.yubico.webauthn.data;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.yubico.util.ByteArray;
import com.yubico.util.exception.Base64UrlException;
import com.yubico.webauthn.impl.WebAuthnCodecs;
import java.io.IOException;
import lombok.NonNull;
import lombok.Value;


@Value
public class AttestationObject {

    @JsonIgnore
    @NonNull
    private final ByteArray bytes;

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

    @NonNull
    @JsonProperty("attStmt")
    private final ObjectNode attestationStatement;

    public AttestationObject(@NonNull ByteArray bytes) throws IOException, Base64UrlException {
        this.bytes = bytes;

        JsonNode decoded = WebAuthnCodecs.cbor().readTree(bytes.getBytes());
        if (!decoded.isObject()) {
            throw new IllegalArgumentException("Attestation object must be a JSON object.");
        }

        JsonNode authData = decoded.get("authData");
        if (authData == null) {
            throw new IllegalArgumentException("Required property \"authData\" missing from attestation object: " + bytes.getBase64Url());
        } else {
            if (authData.isBinary()) {
                this.authData = new ByteArray(authData.binaryValue());
            } else {
                throw new IllegalArgumentException(String.format(
                    "Property \"authData\" of attestation object must be a CBOR byte array, was: %s. Attestation object: %s",
                    authData.getNodeType(),
                    bytes.getBase64Url()
                ));
            }
        }

        JsonNode format = decoded.get("fmt");
        if (format == null) {
            throw new IllegalArgumentException("Required property \"fmt\" missing from attestation object: " + bytes.getBase64Url());
        } else {
            if (format.isTextual()) {
                this.format = decoded.get("fmt").textValue();
            } else {
                throw new IllegalArgumentException(String.format(
                    "Property \"fmt\" of attestation object must be a CBOR text value, was: %s. Attestation object: %s",
                    format.getNodeType(),
                    bytes.getBase64Url()
                ));
            }
        }

        JsonNode attStmt = decoded.get("attStmt");
        if (attStmt == null) {
            throw new IllegalArgumentException("Required property \"attStmt\" missing from attestation object: " + bytes.getBase64Url());
        } else {
            if (attStmt.isObject()) {
                this.attestationStatement = (ObjectNode) attStmt;
            } else {
                throw new IllegalArgumentException(String.format(
                    "Property \"attStmt\" of attestation object must be a CBOR map, was: %s. Attestation object: %s",
                    attStmt.getNodeType(),
                    bytes.getBase64Url()
                ));
            }
        }

        authenticatorData = new AuthenticatorData(this.authData);
    }

}
