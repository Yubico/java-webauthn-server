package com.yubico.webauthn.data

import java.net.URL
import java.util.Optional

import com.yubico.scala.util.JavaConverters._


/**
  * Describes a Relying Party with which a public key credential is associated.
  */
case class RelyingPartyIdentity (

  /**
    * The human-friendly name of the Relaying Party.
    *
    * For example: "Acme Corporation", "Widgets, Inc.", or "Awesome Site".
    */
  override val name: String,

  /**
    * The RP identifier with which credentials are associated.
    */
  id: String,

  /**
    * A URL which resolves to an image associated with the RP.
    *
    * For example, this could be the RP's logo.
    */
  override val icon: Optional[URL] = None.asJava

) extends PublicKeyCredentialEntity
