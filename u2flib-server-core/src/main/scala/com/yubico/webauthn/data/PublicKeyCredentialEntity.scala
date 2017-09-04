package com.yubico.webauthn.data

import java.net.URL
import java.util.Optional


/**
  * Describes a Relying Party with which a public key credential is associated.
  */
case class PublicKeyCredentialEntity(

  /**
    * The human-friendly name of the Relaying Party.
    *
    * For example: "Acme Corporation", "Widgets, Inc.", or "Awesome Site".
    */
  name: String,

  /**
    * The RP identifier with which credentials are associated.
    */
  id: String,

  /**
    * A URL which resolves to an image associated with the RP.
    *
    * For example, this could be the RP's logo.
    */
  icon: Optional[URL],

)
