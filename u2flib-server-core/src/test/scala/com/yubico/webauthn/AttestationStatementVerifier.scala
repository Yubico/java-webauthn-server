package com.yubico.webauthn

import com.yubico.webauthn.data.AttestationObject
import com.yubico.webauthn.data.ArrayBuffer


trait AttestationStatementVerifier {

  def verifyAttestationSignature(attestationObject: AttestationObject, clientDataJsonHash: ArrayBuffer): Boolean

}