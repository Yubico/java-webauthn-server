package com.yubico.webauthn.data;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.yubico.internal.util.ExceptionUtil;
import com.yubico.webauthn.WebAuthnCodecs;
import com.yubico.webauthn.data.exception.Base64UrlException;
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
     * The URL-safe Base64 encoded challenge as provided by the RP.
     */
    @NonNull
    private final ByteArray challenge;

    /**
     * The fully qualified origin of the requester, as identified by the client.
     */
    @NonNull
    private final String origin;

    /**
     * The type of the requested operation, set by the client.
     */
    @NonNull
    private final String type;

    /**
     * Input or output values for or from authenticator extensions, if any.
     */
    @NonNull
    private final Optional<ObjectNode> authenticatorExtensions;

    /**
     * Input or output values for or from client extensions, if any.
     */
    @NonNull
    private final Optional<ObjectNode> clientExtensions;

    /**
     * The URL-safe Base64 encoded TLS token binding ID the client has negotiated with the RP.
     */
    @NonNull
    private final Optional<TokenBindingInfo> tokenBinding;

    public CollectedClientData(
        /**
         * The client data returned from, or to be sent to, the client.
         */
        @NonNull ByteArray clientDataJSON
    ) throws IOException, Base64UrlException {
        this(parseJson(clientDataJSON));
    }

    @JsonCreator
    private CollectedClientData(
        @NonNull @JsonProperty("challenge") ByteArray challenge,
        @NonNull @JsonProperty("origin") String origin,
        @NonNull @JsonProperty("type") String type,
        @NonNull @JsonProperty("authenticatorExtensions") Optional<JsonNode> authenticatorExtensions,
        @NonNull @JsonProperty("clientExtensions") Optional<JsonNode> clientExtensions,
        @NonNull @JsonProperty("tokenBinding") Optional<TokenBindingInfo> tokenBinding
    ) {
        this.challenge = challenge;
        this.origin = origin;
        this.type = type;

        authenticatorExtensions.ifPresent(ae -> {
            ExceptionUtil.assure(
                ae.isObject(),
                "Field \"authenticatorExtensions\" must be an object if present."
            );
        });
        this.authenticatorExtensions = authenticatorExtensions.map(ae -> (ObjectNode) ae).map(WebAuthnCodecs::deepCopy);

        clientExtensions.ifPresent(ce -> {
            ExceptionUtil.assure(
                ce.isObject(),
                "Field \"clientExtensions\" must be an object if present."
            );
        });
        this.clientExtensions = clientExtensions.map(ce -> (ObjectNode) ce).map(WebAuthnCodecs::deepCopy);

        this.tokenBinding = tokenBinding;
    }

    private CollectedClientData(
        @NonNull ObjectNode clientData
    ) throws Base64UrlException {
        this(
            parseChallenge(clientData),
            parseOrigin(clientData),
            parseType(clientData),
            Optional.ofNullable(clientData.get("authenticatorExtensions")),
            Optional.ofNullable(clientData.get("clientExtensions")),
            parseTokenBinding(clientData.get("tokenBinding"))
        );
    }

    private static ObjectNode parseJson(@NonNull ByteArray jsonBytes) throws IOException {
        final JsonNode clientData = WebAuthnCodecs.json().readTree(jsonBytes.getBytes());
        ExceptionUtil.assure(
            clientData != null && clientData.isObject(),
            "Collected client data must be JSON object."
        );
        return (ObjectNode) clientData;
    }

    private static ByteArray parseChallenge(@NonNull JsonNode clientData) throws Base64UrlException {
        try {
            return ByteArray.fromBase64Url(clientData.get("challenge").textValue());
        } catch (NullPointerException e) {
            throw new IllegalArgumentException("Missing field: \"challenge\"");
        } catch (Base64UrlException e) {
            throw new Base64UrlException("Invalid \"challenge\" value", e);
        }
    }

    private static String parseOrigin(@NonNull JsonNode clientData) {
        String origin;
        try {
            origin = clientData.get("origin").textValue();
        } catch (NullPointerException e) {
            throw new IllegalArgumentException("Missing field: \"origin\"");
        }
        return origin;
    }

    private static String parseType(@NonNull JsonNode clientData) {
        try {
            return clientData.get("type").textValue();
        } catch (NullPointerException e) {
            throw new IllegalArgumentException("Missing field: \"type\"");
        }
    }

    public static final Optional<TokenBindingInfo> parseTokenBinding(JsonNode tokenBinding) {
        return Optional.ofNullable(tokenBinding)
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
                    throw new IllegalArgumentException("Property \"tokenBinding\" must be a JSON object if present, was: " + tb);
                }
            });
    }

}
