package com.yubico.webauthn.impl

import com.yubico.scala.util.JavaConverters._
import com.yubico.webauthn.data.AuthenticationExtensionsClientInputs
import com.yubico.webauthn.data.PublicKeyCredential
import com.yubico.webauthn.data.AuthenticatorResponse
import com.yubico.webauthn.util.WebAuthnCodecs

import scala.collection.JavaConverters._


object ExtensionsValidation {

  def validate(requested: Option[AuthenticationExtensionsClientInputs], response: PublicKeyCredential[_ <: AuthenticatorResponse]): Boolean = {
    val requestedExtensionIds: Set[String] = requested map { _.fieldNames.asScala.toSet } getOrElse Set.empty

    val clientExtensionIds: Set[String] = response.clientExtensionResults.fieldNames.asScala.toSet
    assert(
      clientExtensionIds subsetOf requestedExtensionIds,
      s"Client extensions {${clientExtensionIds.toSeq.sorted.mkString(", ")}} are not a subset of requested extensions {${requestedExtensionIds.toSeq.sorted.mkString(", ")}}."
    )

    val authenticatorExtensionIds: Set[String] =
      response.response.parsedAuthenticatorData.extensions.asScala
        .map(_.toArray)
        .map(WebAuthnCodecs.cbor.readTree)
        .map(_.fieldNames.asScala.toSet)
        .getOrElse(Set.empty)
    assert(
      authenticatorExtensionIds subsetOf requestedExtensionIds,
      s"Authenticator extensions {${authenticatorExtensionIds.toSeq.sorted.mkString(", ")}} are not a subset of requested extensions {${requestedExtensionIds.toSeq.sorted.mkString(", ")}}."
    )

    true
  }

}
