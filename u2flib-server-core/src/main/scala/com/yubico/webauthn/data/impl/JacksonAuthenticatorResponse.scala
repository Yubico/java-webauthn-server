package com.yubico.webauthn.data.impl
import java.io.ByteArrayInputStream

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import com.yubico.webauthn.data.AuthenticatorResponse

trait JacksonAuthenticatorResponse extends AuthenticatorResponse {

  override lazy val clientData: JsonNode =
    new ObjectMapper().readTree(new ByteArrayInputStream(clientDataJSON.toArray))
}
