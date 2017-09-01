package com.yubico.webauthn.data.impl
import java.io.ByteArrayInputStream

import com.fasterxml.jackson.databind.JsonNode
import com.yubico.webauthn.data.AuthenticatorResponse
import com.yubico.webauthn.util.WebAuthnCodecs


trait JacksonAuthenticatorResponse extends AuthenticatorResponse {

  override lazy val clientData: JsonNode =
    WebAuthnCodecs.json.readTree(new ByteArrayInputStream(clientDataJSON.toArray))
}
