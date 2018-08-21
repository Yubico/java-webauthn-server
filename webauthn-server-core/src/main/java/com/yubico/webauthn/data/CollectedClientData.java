package com.yubico.webauthn.data;

import com.fasterxml.jackson.databind.JsonNode;
import com.yubico.webauthn.exception.Base64UrlException;
import com.yubico.webauthn.impl.util.WebAuthnCodecs;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Optional;
import lombok.NonNull;
import lombok.Value;

/**
 * High-level API for reading W3C specified values out of client data.
 */
@Value
public class CollectedClientData {

    /**
     * @param The client data returned from, or to be sent to, the client.
     */
    @NonNull
    private JsonNode clientData;

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

    public CollectedClientData(@NonNull ByteArray clientDataJSON) throws IOException, Base64UrlException {
        this(WebAuthnCodecs.json().readTree(new ByteArrayInputStream(clientDataJSON.getBytes())));
    }

    public CollectedClientData(@NonNull JsonNode clientData) throws Base64UrlException {
        this.clientData = clientData;

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
    }

    /**
     * Input or output values for or from authenticator extensions, if any.
     */
    public Optional<JsonNode> getAuthenticatorExtensions() {
        return Optional.ofNullable(clientData.get("authenticatorExtensions")).map(WebAuthnCodecs::deepCopy);
    }

    /**
     * Input or output values for or from client extensions, if any.
     */
    public Optional<JsonNode> getClientExtensions() {
        return Optional.ofNullable(clientData.get("clientExtensions")).map(WebAuthnCodecs::deepCopy);
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

}
