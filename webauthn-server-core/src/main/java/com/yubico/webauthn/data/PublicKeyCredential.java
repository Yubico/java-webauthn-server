package com.yubico.webauthn.data;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import com.yubico.webauthn.impl.util.WebAuthnCodecs;
import lombok.Builder;
import lombok.NonNull;
import lombok.Value;


@Value
@Builder
public class PublicKeyCredential<A extends AuthenticatorResponse> implements Credential {

    /**
     * This attribute is inherited from `Credential`, though PublicKeyCredential overrides `Credential`'s getter,
     * instead returning the base64url encoding of the [[rawId]].
     */
    @NonNull
    private final ByteArray id;

    /**
     * The authenticator's response to the client’s request to either create a public key credential, or generate an
     * authentication assertion.
     * <p>
     * If the PublicKeyCredential is created in response to create(), this attribute’s value will be an
     * [[AuthenticatorAttestationResponse]], otherwise, the PublicKeyCredential was created in response to get(), and
     * this attribute’s value will be an [[AuthenticatorAssertionResponse]].
     */
    @NonNull
    private final A response;

    /**
     * A map containing extension identifier → client extension output entries produced by the extension’s client
     * extension processing.
     */
    @NonNull
    private final JsonNode clientExtensionResults;

    /**
     * The PublicKeyCredential's type value is the string "public-key".
     */
    @NonNull
    private final PublicKeyCredentialType type;

    public PublicKeyCredential(
        @NonNull ByteArray id,
        @NonNull A response,
        @NonNull JsonNode clientExtensionResults
    ) {
        this(id, response, clientExtensionResults, PublicKeyCredentialType.PUBLIC_KEY);
    }

    @JsonCreator
    private PublicKeyCredential(
        @NonNull @JsonProperty("id") ByteArray id,
        @NonNull @JsonProperty("response") A response,
        @NonNull @JsonProperty("clientExtensionResults") JsonNode clientExtensionResults,
        @NonNull @JsonProperty("type") PublicKeyCredentialType type
    ) {
        this.id = id;
        this.response = response;
        this.clientExtensionResults = clientExtensionResults;
        this.type = type;
    }

    public JsonNode getClientExtensionResults() {
        return WebAuthnCodecs.deepCopy(clientExtensionResults);
    }

}
