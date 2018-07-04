package com.yubico.webauthn.impl

import java.util.Optional

import com.yubico.scala.util.JavaConverters._
import com.yubico.webauthn.data.TokenBindingInfo
import com.yubico.webauthn.data.TokenBindingStatus


object TokenBindingValidator {

  def validate(clientTokenBinding: Optional[TokenBindingInfo], rpTokenBindingId: Optional[String]): Boolean =
    rpTokenBindingId.asScala match {
      case None =>
        clientTokenBinding.asScala match {
          case None => true
          case Some(tbi) =>
            tbi.getStatus match {
              case TokenBindingStatus.SUPPORTED | TokenBindingStatus.NOT_SUPPORTED => true
              case TokenBindingStatus.PRESENT => throw new AssertionError("Token binding ID set by client but not by RP.")
            }
        }

      case Some(rpToken) =>
        clientTokenBinding.asScala match {
          case None => throw new AssertionError("Token binding ID set by RP but not by client.")
          case Some(tbi) =>
            tbi.getStatus match {
              case TokenBindingStatus.SUPPORTED | TokenBindingStatus.NOT_SUPPORTED => throw new AssertionError("Token binding ID set by RP but not by client.")
              case TokenBindingStatus.PRESENT =>
                tbi.getId.asScala match {
                  case None => throw new AssertionError("""Property "id" missing from "tokenBinding" object.""")
                  case Some(id) =>
                    assert(rpToken == id, "Incorrect token binding ID.")
                    true
                }
            }
        }
    }

}
