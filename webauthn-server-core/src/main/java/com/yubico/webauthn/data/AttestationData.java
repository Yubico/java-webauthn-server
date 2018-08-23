package com.yubico.webauthn.data;

import COSE.CoseException;
import com.yubico.util.ByteArray;
import com.yubico.webauthn.impl.util.WebAuthnCodecs;
import java.io.IOException;
import java.security.interfaces.ECPublicKey;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.NonNull;
import lombok.Value;

@Value
@AllArgsConstructor(access = AccessLevel.PRIVATE)
@Builder
public class AttestationData {

    /**
     * The AAGUID of the authenticator.
     */
    @NonNull
    private final ByteArray aaguid;

    /**
     * The ID of the attested credential.
     */
    @NonNull
    private final ByteArray credentialId;

    /**
     * The ''credential public key'' encoded in COSE_Key format.
     *
     * @todo verify requirements https://www.w3.org/TR/webauthn/#sec-attestation-data
     */
    @NonNull
    private final ByteArray credentialPublicKey;

    public ECPublicKey getParsedCredentialPublicKey() throws IOException, CoseException {
        return WebAuthnCodecs.importCoseP256PublicKey(credentialPublicKey);
    }

}
