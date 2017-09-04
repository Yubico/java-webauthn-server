package com.yubico.webauthn.data

import java.util.Optional

import com.yubico.scala.util.JavaConverters._


/**
  * The attributes that are specified by a caller when referring to a credential
  * as an input parameter to the create() or get() methods. It mirrors the
  * fields of the [[PublicKeyCredential]] object returned by the latter methods.
  */
case class PublicKeyCredentialDescriptor(

  /**
    * The type of the credential the caller is referring to.
    */
  `type`: PublicKeyCredentialType,

  /**
    * The identifier of the credential that the caller is referring to.
    */
  id: ArrayBuffer,

  transports: Optional[Vector[AuthenticatorTransport]] = None.asJava,

)
