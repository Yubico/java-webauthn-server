package com.yubico.webauthn.impl;

import com.yubico.util.ByteArray;
import com.yubico.webauthn.AttestationStatementVerifier;
import com.yubico.webauthn.data.AttestationObject;
import com.yubico.webauthn.data.AttestationType;


public class NoneAttestationStatementVerifier implements AttestationStatementVerifier {

    @Override
    public AttestationType getAttestationType(AttestationObject attestation) {
        return AttestationType.NONE;
    }

    @Override
    public boolean verifyAttestationSignature(AttestationObject attestationObject, ByteArray clientDataJsonHash) {
        return true;
    }

}
