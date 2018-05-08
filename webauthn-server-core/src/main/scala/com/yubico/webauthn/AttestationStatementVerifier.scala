package com.yubico.webauthn

import com.yubico.webauthn.data.AttestationObject
import com.yubico.webauthn.data.ArrayBuffer
import com.yubico.webauthn.data.AttestationType


trait AttestationStatementVerifier {

  def getAttestationType(attestation: AttestationObject): AttestationType
  def verifyAttestationSignature(attestationObject: AttestationObject, clientDataJsonHash: ArrayBuffer): Boolean

}
