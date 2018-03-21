package com.yubico.webauthn.data

object TokenBindingStatus {
  def fromJson(value: String): Option[TokenBindingStatus] =
    List(NotSupported, Present, Supported) find { _.jsonValue == value }
}

sealed trait TokenBindingStatus {
  def jsonValue: String
  def toJson: String = jsonValue
}
object NotSupported extends TokenBindingStatus { override val jsonValue = "not-supported" }
object Present extends TokenBindingStatus      { override val jsonValue = "present"       }
object Supported extends TokenBindingStatus    { override val jsonValue = "supported"     }
