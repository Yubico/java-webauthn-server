package com.yubico.webauthn.data

import java.util.Optional
import com.yubico.scala.util.JavaConverters._


object TokenBindingValidator {

  def validate(clientTokenBinding: Optional[TokenBindingInfo], rpTokenBindingId: Optional[String]): Boolean =
    rpTokenBindingId.asScala match {
      case None =>
        clientTokenBinding.asScala match {
          case None => true
          case Some(TokenBindingInfo(Supported | NotSupported, _)) => true
          case Some(TokenBindingInfo(Present, _)) => throw new AssertionError("Token binding ID set by client but not by RP.")
        }

      case Some(rpToken) =>
        clientTokenBinding.asScala match {
          case None => throw new AssertionError("Token binding ID set by RP but not by client.")
          case Some(TokenBindingInfo(Supported | NotSupported, _)) => throw new AssertionError("Token binding ID set by RP but not by client.")
          case Some(TokenBindingInfo(Present, None)) => throw new AssertionError("""Property "id" missing from "tokenBinding" object.""")
          case Some(TokenBindingInfo(Present, Some(id))) => {
            assert(rpToken == id, "Incorrect token binding ID.")
            true
          }
        }
    }

}
