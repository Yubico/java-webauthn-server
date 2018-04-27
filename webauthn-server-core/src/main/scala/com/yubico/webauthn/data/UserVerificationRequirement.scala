package com.yubico.webauthn.data

import com.fasterxml.jackson.core.JsonGenerator
import com.fasterxml.jackson.databind.JsonSerializer
import com.fasterxml.jackson.databind.SerializerProvider
import com.fasterxml.jackson.databind.annotation.JsonSerialize

private class UVRSerializer extends JsonSerializer[UserVerificationRequirement] {
  override def serialize(t: UserVerificationRequirement, jsonGenerator: JsonGenerator, serializerProvider: SerializerProvider): Unit =
    jsonGenerator.writeString(
      t match {
        case Discouraged => "discouraged"
        case Preferred => "preferred"
        case Required => "required"
      }
    )
}

object UserVerificationRequirement {
  val default: UserVerificationRequirement = Preferred
}

@JsonSerialize(using = classOf[UVRSerializer])
sealed trait UserVerificationRequirement
case object Discouraged extends UserVerificationRequirement
case object Preferred extends UserVerificationRequirement
case object Required extends UserVerificationRequirement
