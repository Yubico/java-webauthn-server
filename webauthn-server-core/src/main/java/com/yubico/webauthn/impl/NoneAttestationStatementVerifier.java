package com.yubico.webauthn.impl;

import com.yubico.webauthn.AttestationStatementVerifier;
import com.yubico.webauthn.data.AttestationObject;
import com.yubico.webauthn.data.AttestationType;


public class NoneAttestationStatementVerifier implements AttestationStatementVerifier {

    @Override
    public AttestationType getAttestationType(AttestationObject attestation) {
        return AttestationType.NONE;
    }

    @Override
    public boolean verifyAttestationSignature(AttestationObject attestationObject, byte[] clientDataJsonHash) {
        return true;
    }

}
