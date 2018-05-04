package com.yubico.webauthn.data

import java.net.URL
import java.util.Optional

import com.fasterxml.jackson.annotation.JsonIgnore
import com.fasterxml.jackson.annotation.JsonProperty
import com.yubico.scala.util.JavaConverters._
import com.yubico.u2f.data.messages.key.util.U2fB64Encoding


/**
  * Describes a user account, with which a public key credential is to be associated.
  */
case class UserIdentity (

  /**
    * A name for the user account.
    *
    * For example: "john.p.smith@example.com" or "+14255551234".
    */
  override val name: String,

  /**
    * A friendly name for the user account (e.g. "Ryan A. Smith").
    */
  displayName: String,

  /**
    * An identifier for the account, specified by the Relying Party.
    *
    * This is not meant to be displayed to the user, but is used by the Relying
    * Party to control the number of credentials - an authenticator will never
    * contain more than one credential for a given Relying Party under the same
    * id.
    */
  @JsonIgnore
  id: ArrayBuffer,

  /**
    * A URL which resolves to an image associated with the user account.
    *
    * For example, this could be the user's avatar.
    */
  override val icon: Optional[URL] = None.asJava

) extends PublicKeyCredentialEntity {

  def this(name: String, displayName: String, id: Array[Byte], icon: Optional[URL]) =
    this(name, displayName, id.toVector, icon)

  @JsonProperty("id")
  def idBase64: String = U2fB64Encoding.encode(id.toArray)
}
