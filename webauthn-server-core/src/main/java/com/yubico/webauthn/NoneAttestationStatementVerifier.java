package com.yubico.webauthn;

import com.yubico.webauthn.data.AttestationObject;
import com.yubico.webauthn.data.AttestationType;
import com.yubico.webauthn.data.ByteArray;


class NoneAttestationStatementVerifier implements AttestationStatementVerifier {

    @Override
    public AttestationType getAttestationType(AttestationObject attestation) {
        return AttestationType.NONE;
    }

    @Override
    public boolean verifyAttestationSignature(AttestationObject attestationObject, ByteArray clientDataJsonHash) {
        return true;
    }

}
