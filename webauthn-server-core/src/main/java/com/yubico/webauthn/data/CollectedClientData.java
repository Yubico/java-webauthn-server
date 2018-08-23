package com.yubico.webauthn.data;

import com.fasterxml.jackson.databind.JsonNode;
import com.yubico.u2f.data.messages.key.util.U2fB64Encoding;
import com.yubico.u2f.exceptions.U2fBadInputException;
import com.yubico.webauthn.util.WebAuthnCodecs;
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
    private JsonNode clientData;

    public CollectedClientData(@NonNull JsonNode clientData) throws U2fBadInputException {
        this.clientData = clientData;

        try {
            getChallenge();
        } catch (NullPointerException e) {
            throw new IllegalArgumentException("Missing field: \"challenge\"");
        }

        try {
            getOrigin();
        } catch (NullPointerException e) {
            throw new IllegalArgumentException("Missing field: \"origin\"");
        }

        try {
            getType();
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
     * The URL-safe Base64 encoded challenge as provided by the RP.
     */
    public String getChallengeBase64() {
        return clientData.get("challenge").asText();
    }

    /**
     * The URL-safe Base64 encoded challenge as provided by the RP.
     */
    public byte[] getChallenge() throws U2fBadInputException {
        return U2fB64Encoding.decode(getChallengeBase64());
    }

    /**
     * Input or output values for or from client extensions, if any.
     */
    public Optional<JsonNode> getClientExtensions() {
        return Optional.ofNullable(clientData.get("clientExtensions")).map(WebAuthnCodecs::deepCopy);
    }

    /**
     * The fully qualified origin of the requester, as identified by the client.
     */
    public String getOrigin() {
        return clientData.get("origin").asText();
    }

    /**
     * The URL-safe Base64 encoded TLS token binding ID the client has negotiated with the RP.
     */
    public final Optional<TokenBindingInfo> getTokenBinding() {
        return Optional.ofNullable(clientData.get("tokenBinding"))
            .map(tb -> {
                if (tb != null && tb.isObject()) {
                    String status = tb.get("status").textValue();
                    return new TokenBindingInfo(
                        TokenBindingStatus.fromJson(status).orElseGet(() -> {
                            throw new IllegalArgumentException("Invalid value for tokenBinding.status: " + status);
                        }),
                        Optional.ofNullable(tb.get("id")).map(JsonNode::textValue)
                    );
                } else {
                    throw new IllegalArgumentException("Property \"tokenBinding\" missing from client data.");
                }
            });
    }

    /**
     * The type of the requested operation, set by the client.
     */
    public final String getType() {
        return clientData.get("type").asText();
    }

}
