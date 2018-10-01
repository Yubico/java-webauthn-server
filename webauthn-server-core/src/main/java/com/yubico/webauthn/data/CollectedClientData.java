package com.yubico.webauthn.data;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.yubico.internal.util.ExceptionUtil;
import com.yubico.internal.util.WebAuthnCodecs;
import com.yubico.webauthn.data.exception.Base64UrlException;
import java.io.IOException;
import java.util.Optional;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NonNull;
import lombok.Value;

/**
 * High-level API for reading W3C specified values out of client data.
 */
@Value
@JsonSerialize(using = CollectedClientData.JsonSerializer.class)
public class CollectedClientData {

    /**
     * The client data returned from, or to be sent to, the client.
     */
    @NonNull
    @Getter(AccessLevel.NONE)
    private final ByteArray clientDataJson;

    @NonNull
    @Getter(AccessLevel.NONE)
    private final ObjectNode clientData;

    /**
     * The URL-safe Base64 encoded challenge as provided by the RP.
     */
    @NonNull
    private final transient ByteArray challenge;

    /**
     * The fully qualified origin of the requester, as identified by the client.
     */
    @NonNull
    private final transient String origin;

    /**
     * The type of the requested operation, set by the client.
     */
    @NonNull
    private final transient String type;

    @JsonCreator
    public CollectedClientData(@NonNull ByteArray clientDataJSON) throws IOException, Base64UrlException {
        JsonNode clientData = WebAuthnCodecs.json().readTree(clientDataJSON.getBytes());

        ExceptionUtil.assure(
            clientData != null && clientData.isObject(),
            "Collected client data must be JSON object."
        );

        this.clientDataJson = clientDataJSON;
        this.clientData = (ObjectNode) clientData;

        try {
            challenge = ByteArray.fromBase64Url(clientData.get("challenge").textValue());
        } catch (NullPointerException e) {
            throw new IllegalArgumentException("Missing field: \"challenge\"");
        } catch (Base64UrlException e) {
            throw new Base64UrlException("Invalid \"challenge\" value", e);
        }

        try {
            origin = clientData.get("origin").textValue();
        } catch (NullPointerException e) {
            throw new IllegalArgumentException("Missing field: \"origin\"");
        }

        try {
            type = clientData.get("type").textValue();
        } catch (NullPointerException e) {
            throw new IllegalArgumentException("Missing field: \"type\"");
        }

        final JsonNode authenticatorExtensions = clientData.get("authenticatorExtensions");
        if (authenticatorExtensions != null && !authenticatorExtensions.isObject()) {
            throw new IllegalArgumentException("Field \"authenticatorExtensions\" must be an object if present.");
        }

        final JsonNode clientExtensions = clientData.get("clientExtensions");
        if (clientExtensions != null && !clientExtensions.isObject()) {
            throw new IllegalArgumentException("Field \"clientExtensions\" must be an object if present.");
        }
    }

    /**
     * The URL-safe Base64 encoded TLS token binding ID the client has negotiated with the RP.
     */
    public final Optional<TokenBindingInfo> getTokenBinding() {
        return Optional.ofNullable(clientData.get("tokenBinding"))
            .map(tb -> {
                if (tb.isObject()) {
                    String status = tb.get("status").textValue();
                    return new TokenBindingInfo(
                        TokenBindingStatus.fromJsonString(status),
                        Optional.ofNullable(tb.get("id"))
                            .map(JsonNode::textValue)
                            .map(id -> {
                                try {
                                    return ByteArray.fromBase64Url(id);
                                } catch (Base64UrlException e) {
                                    throw new IllegalArgumentException("Property \"id\" is not valid Base64Url data", e);
                                }
                            })
                    );
                } else {
                    throw new IllegalArgumentException("Property \"tokenBinding\" missing from client data.");
                }
            });
    }

    static class JsonSerializer extends com.fasterxml.jackson.databind.JsonSerializer<CollectedClientData> {
        @Override
        public void serialize(CollectedClientData value, JsonGenerator gen, SerializerProvider serializers) throws IOException {
            gen.writeString(value.clientDataJson.getBase64Url());
        }
    }

}
