package com.yubico.webauthn.impl

import com.yubico.webauthn.AttestationStatementVerifier
import com.yubico.webauthn.data.AttestationObject
import com.yubico.webauthn.data.ArrayBuffer
import com.yubico.webauthn.data.AttestationType
import com.yubico.webauthn.data.NoneAttestation


object NoneAttestationStatementVerifier extends AttestationStatementVerifier {

  override def getAttestationType(attestation: AttestationObject): AttestationType = NoneAttestation

  override def verifyAttestationSignature(attestationObject: AttestationObject, clientDataJsonHash: ArrayBuffer): Boolean = true

}
