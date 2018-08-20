package com.yubico.webauthn.data;

import COSE.CoseException;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.yubico.u2f.data.messages.key.util.U2fB64Encoding;
import com.yubico.webauthn.util.BinaryUtil;
import com.yubico.webauthn.util.WebAuthnCodecs;
import java.io.IOException;
import java.security.interfaces.ECPublicKey;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.Value;

@Value
@Builder
public class AttestationData {

    /**
     * The AAGUID of the authenticator.
     */
    @JsonIgnore
    private byte[] aaguid;

    /**
     * The ID of the attested credential.
     */
    @JsonIgnore
    private byte[] credentialId;

    /**
     * The ''credential public key'' encoded in COSE_Key format.
     *
     * @todo verify requirements https://www.w3.org/TR/webauthn/#sec-attestation-data
     */
    @JsonIgnore
    @Getter(AccessLevel.NONE)
    private byte[] credentialPublicKey;

    @JsonProperty("aaguid")
    public String getAaguidBase64() {
        return U2fB64Encoding.encode(aaguid);
    }

    @JsonProperty("credentialId")
    public String getCredentialIdBase64() {
        return U2fB64Encoding.encode(credentialId);
    }

    @JsonProperty("credentialPublicKey")
    public String getCredentialPublicKeyBase64() {
        return U2fB64Encoding.encode(credentialPublicKey);
    }

    public byte[] getAaguid() {
        return BinaryUtil.copy(aaguid);
    }

    public byte[] getCredentialId() {
        return BinaryUtil.copy(credentialId);
    }

    public byte[] getCredentialPublicKeyBytes() {
        return BinaryUtil.copy(credentialPublicKey);
    }

    public ECPublicKey getParsedCredentialPublicKey() throws IOException, CoseException {
        return WebAuthnCodecs.importCoseP256PublicKey(credentialPublicKey);
    }

}
