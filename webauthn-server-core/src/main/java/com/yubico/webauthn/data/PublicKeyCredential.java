package com.yubico.webauthn.data;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import com.yubico.webauthn.util.WebAuthnCodecs;
import lombok.Value;


@Value
public class PublicKeyCredential<A extends AuthenticatorResponse> implements Credential {

    /**
     * This attribute is inherited from `Credential`, though PublicKeyCredential overrides `Credential`'s getter,
     * instead returning the base64url encoding of the [[rawId]].
     */
    private ByteArray id;

    /**
     * The authenticator's response to the client’s request to either create a public key credential, or generate an
     * authentication assertion.
     * <p>
     * If the PublicKeyCredential is created in response to create(), this attribute’s value will be an
     * [[AuthenticatorAttestationResponse]], otherwise, the PublicKeyCredential was created in response to get(), and
     * this attribute’s value will be an [[AuthenticatorAssertionResponse]].
     */
    private A response;

    /**
     * A map containing extension identifier → client extension output entries produced by the extension’s client
     * extension processing.
     */
    private JsonNode clientExtensionResults;

    @JsonCreator
    public PublicKeyCredential(
        @JsonProperty ByteArray id,
        @JsonProperty A response,
        @JsonProperty JsonNode clientExtensionResults
    ) {
        this.id = id;
        this.response = response;
        this.clientExtensionResults = clientExtensionResults;
    }

    public JsonNode getClientExtensionResults() {
        return WebAuthnCodecs.deepCopy(clientExtensionResults);
    }

    /**
     * The PublicKeyCredential's type value is the string "public-key".
     */
    @Override
    public String getType() {
        return "public-key";
    }

}
