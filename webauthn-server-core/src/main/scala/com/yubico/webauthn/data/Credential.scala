package com.yubico.webauthn.data

trait Credential {
  val id: String
  val `type`: String
}
