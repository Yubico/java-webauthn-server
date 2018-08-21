package com.yubico.webauthn.data;

import COSE.CoseException;
import com.yubico.webauthn.impl.util.WebAuthnCodecs;
import java.io.IOException;
import java.security.interfaces.ECPublicKey;
import lombok.Builder;
import lombok.Value;

@Value
@Builder
public class AttestationData {

    /**
     * The AAGUID of the authenticator.
     */
    private ByteArray aaguid;

    /**
     * The ID of the attested credential.
     */
    private ByteArray credentialId;

    /**
     * The ''credential public key'' encoded in COSE_Key format.
     *
     * @todo verify requirements https://www.w3.org/TR/webauthn/#sec-attestation-data
     */
    private ByteArray credentialPublicKey;

    public ECPublicKey getParsedCredentialPublicKey() throws IOException, CoseException {
        return WebAuthnCodecs.importCoseP256PublicKey(credentialPublicKey);
    }

}
