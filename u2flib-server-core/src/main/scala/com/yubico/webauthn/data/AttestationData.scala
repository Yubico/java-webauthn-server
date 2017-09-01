package com.yubico.webauthn.data

import com.fasterxml.jackson.databind.JsonNode

case class AttestationData private[data] (

  /**
    * The AAGUID of the authenticator.
    */
  aaguid: ArrayBuffer,

  /**
    * The ID of the attested credential.
    */
  credentialId: ArrayBuffer,

  /**
    * The ''credential public key'' encoded in COSE_Key format.
    *
    * @todo verify requirements https://www.w3.org/TR/webauthn/#sec-attestation-data
    */
  credentialPublicKey: JsonNode,

)
