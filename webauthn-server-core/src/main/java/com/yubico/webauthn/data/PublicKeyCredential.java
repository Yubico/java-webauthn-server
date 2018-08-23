package com.yubico.webauthn.data;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import com.yubico.u2f.data.messages.key.util.U2fB64Encoding;
import com.yubico.u2f.exceptions.U2fBadInputException;
import com.yubico.webauthn.util.BinaryUtil;
import com.yubico.webauthn.util.WebAuthnCodecs;
import lombok.Value;


@Value
public class PublicKeyCredential<A extends AuthenticatorResponse> implements Credential {

    /**
     * An identifier for the credential, chosen by the client.
     * <p>
     * This identifier is used to look up credentials for use, and is therefore expected to be globally unique with high
     * probability across all credentials of the same type, across all authenticators. This API does not constrain the
     * format or length of this identifier, except that it must be sufficient for the platform to uniquely select a key.
     * For example, an authenticator without on-board storage may create identifiers containing a credential private key
     * wrapped with a symmetric key that is burned into the authenticator.
     */
    @JsonIgnore
    private byte[] rawId;

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
        @JsonProperty("id") String idBase64,
        @JsonProperty A response,
        @JsonProperty JsonNode clientExtensionResults
    ) throws U2fBadInputException {
        this.rawId = U2fB64Encoding.decode(idBase64);
        this.response = response;
        this.clientExtensionResults = clientExtensionResults;
    }

    public byte[] getRawId() {
        return BinaryUtil.copy(rawId);
    }

    /**
     * This attribute is inherited from `Credential`, though PublicKeyCredential overrides `Credential`'s getter,
     * instead returning the base64url encoding of the [[rawId]].
     */
    @Override
    public String getId() {
        return U2fB64Encoding.encode(rawId);
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
