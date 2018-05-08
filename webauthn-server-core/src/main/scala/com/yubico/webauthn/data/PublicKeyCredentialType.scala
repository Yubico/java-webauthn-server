package com.yubico.webauthn.data

import java.util.Optional

import com.yubico.scala.util.JavaConverters._


/**
  * Defines the valid credential types.
  *
  * It is an extensions point; values may be added to it in the future, as more
  * credential types are defined. The values of this enumeration are used for
  * versioning the Authentication Assertion and attestation structures
  * according to the type of the authenticator.
  *
  * Currently one credential type is defined, namely [[PublicKey]].
  */
object PublicKeyCredentialType {

  def apply(id: String): Optional[PublicKeyCredentialType] = List(PublicKey).find(_.id == id).asJava

}

/**
  * @see [[PublicKeyCredentialType]]
  */
sealed trait PublicKeyCredentialType {
  def id: String
}

case object PublicKey extends PublicKeyCredentialType {
  override def id = "public-key"
}
