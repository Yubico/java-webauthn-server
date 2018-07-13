package com.yubico.webauthn;

import com.yubico.webauthn.data.AttestationObject;
import com.yubico.webauthn.data.AttestationType;


public interface AttestationStatementVerifier {

  AttestationType getAttestationType(AttestationObject attestation);
  boolean verifyAttestationSignature(AttestationObject attestationObject, byte[] clientDataJsonHash);

}
