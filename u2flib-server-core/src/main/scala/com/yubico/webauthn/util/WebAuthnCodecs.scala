package com.yubico.webauthn.util

import com.fasterxml.jackson.core.Base64Variants
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.dataformat.cbor.CBORFactory


object WebAuthnCodecs {

  def cbor: ObjectMapper = new ObjectMapper(new CBORFactory())

  def json: ObjectMapper = new ObjectMapper()

}
