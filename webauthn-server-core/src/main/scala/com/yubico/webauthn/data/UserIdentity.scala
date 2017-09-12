package com.yubico.webauthn.data

import java.net.URL
import java.util.Optional

import com.yubico.scala.util.JavaConverters._


/**
  * Describes a user account, with which a public key credential is to be associated.
  */
case class UserIdentity (

  /**
    * A name for the user account.
    *
    * For example: "john.p.smith@example.com" or "+14255551234".
    */
  name: String,

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
  id: String,

  /**
    * A URL which resolves to an image associated with the user account.
    *
    * For example, this could be the user's avatar.
    */
  icon: Optional[URL] = None.asJava

)
