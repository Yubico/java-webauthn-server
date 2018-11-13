// Copyright (c) 2018, Yubico AB
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

package com.yubico.webauthn.data;

import java.net.URL;
import java.util.Optional;


public interface PublicKeyCredentialEntity {

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
  String getName();

  /**
    * A serialized URL which resolves to an image associated with the entity.
    *
    * For example, this could be a user’s avatar or a Relying Party's logo. This
    * URL MUST be an a priori authenticated URL. Authenticators MUST accept and
    * store a 128-byte minimum length for an icon member’s value. Authenticators
    * MAY ignore an icon member’s value if its length is greater than 128 bytes.
    */
  Optional<URL> getIcon();

}
