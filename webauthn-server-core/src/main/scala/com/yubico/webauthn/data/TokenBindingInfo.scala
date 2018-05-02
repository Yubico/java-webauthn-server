package com.yubico.webauthn.data

case class TokenBindingInfo(status: TokenBindingStatus, id: Option[String])
