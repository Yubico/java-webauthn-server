package com.yubico.webauthn.data

import java.net.URL
import java.util.Optional


trait PublicKeyCredentialEntity {

  /**
    * A human-readable name for the entity. Its function depends on what the PublicKeyCredentialEntity represents:
    *
    * When inherited by PublicKeyCredentialRpEntity it is a human-friendly
    * identifier for the Relying Party, intended only for display. For example,
    * "ACME Corporation", "Wonderful Widgets, Inc." or "Awesome Site".
    *
    * When inherited by PublicKeyCredentialUserEntity, it is a human-palatable
    * identifier for a user account. It is intended only for display, and SHOULD
    * allow the user to easily tell the difference between user accounts with
    * similar displayNames. For example, "alexm", "alex.p.mueller@example.com"
    * or "+14255551234". The Relying Party MAY let the user choose this, and MAY
    * restrict the choice as needed or appropriate. For example, a Relying Party
    * might choose to map human-palatable username account identifiers to the
    * name member of PublicKeyCredentialUserEntity.
    *
    * Authenticators MUST accept and store a 64-byte minimum length for a name
    * member’s value. Authenticators MAY truncate a name member’s value to a
    * length equal to or greater than 64 bytes.
    */
  val name: String

  /**
    * A serialized URL which resolves to an image associated with the entity.
    *
    * For example, this could be a user’s avatar or a Relying Party's logo. This
    * URL MUST be an a priori authenticated URL. Authenticators MUST accept and
    * store a 128-byte minimum length for an icon member’s value. Authenticators
    * MAY ignore an icon member’s value if its length is greater than 128 bytes.
    */
  val icon: Optional[URL]

}
