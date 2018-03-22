package com.yubico.webauthn

import com.fasterxml.jackson.databind.JsonNode
import com.yubico.scala.util.JavaConverters._
import com.yubico.webauthn.data.AuthenticationExtensions
import com.yubico.webauthn.data.PublicKeyCredential
import com.yubico.webauthn.data.AuthenticatorResponse
import com.yubico.webauthn.util.WebAuthnCodecs

import scala.collection.JavaConverters._


object ExtensionsValidation {

  def validate(requested: Option[AuthenticationExtensions], response: PublicKeyCredential[_ <: AuthenticatorResponse]): Boolean = {
    assert(
      requested.isDefined,
      "Extensions were returned, but not requested."
    )

    assert(
      response.clientExtensionResults.fieldNames.asScala.toSet subsetOf requested.map(_.fieldNames.asScala.toSet).getOrElse(Set.empty),
      "Client extensions are not a subset of requested extensions."
    )

    for {
      cbor <- response.response.parsedAuthenticatorData.extensions.asScala
      cborArray = cbor.toArray
      extensions: JsonNode = WebAuthnCodecs.cbor.readTree(cborArray)
    } {
      assert(requested.isDefined, "Extensions were returned, but not requested.")

      assert(
        extensions.fieldNames.asScala.toSet subsetOf requested.get.fieldNames.asScala.toSet,
        "Authenticator extensions are not a subset of requested extensions."
      )
    }

    true
  }

}
