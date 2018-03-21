package com.yubico.webauthn.data

case class TokenBindingInfo(status: TokenBindingStatus, id: Option[String]) {

  def validate(callerTokenBindingId: Option[String]): Boolean =
    (callerTokenBindingId, status) match {
      case (Some(callerToken), Present) =>
        id match {
          case Some(id) => {
            assert(callerToken == id, "Incorrect token binding ID.")
            true
          }
          case None => throw new AssertionError("""Property "id" missing from "tokenBinding" object.""")
        }
      case (None, Present) => throw new AssertionError("Token binding ID set in attestation message but not by caller.")
      case (None, Supported | NotSupported) => true
      case (Some(_), _) => throw new AssertionError("Token binding ID set by caller but not in attestation message.")
    }

}
