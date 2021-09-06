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

/**
 * Describes a user account, or a WebAuthn Relying Party, which a public key credential is
 * associated with or scoped to, respectively.
 *
 * @see <a
 *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#dictdef-publickeycredentialentity">§5.4.1.
 *     Public Key Entity Description (dictionary PublicKeyCredentialEntity) </a>
 */
public interface PublicKeyCredentialEntity {

  /**
   * A human-palatable name for the entity. Its function depends on what the
   * PublicKeyCredentialEntity represents:
   *
   * <ul>
   *   <li>When inherited by PublicKeyCredentialRpEntity it is a human-palatable identifier for the
   *       Relying Party, intended only for display. For example, "ACME Corporation", "Wonderful
   *       Widgets, Inc." or "ОАО Примертех".
   *       <ul>
   *         <li>Relying Parties SHOULD perform enforcement, as prescribed in Section 2.3 of
   *             [RFC8266] for the Nickname Profile of the PRECIS FreeformClass [RFC8264], when
   *             setting name's value, or displaying the value to the user.
   *         <li>Clients SHOULD perform enforcement, as prescribed in Section 2.3 of [RFC8266] for
   *             the Nickname Profile of the PRECIS FreeformClass [RFC8264], on name's value prior
   *             to displaying the value to the user or including the value as a parameter of the
   *             authenticatorMakeCredential operation.
   *       </ul>
   *   <li>When inherited by PublicKeyCredentialUserEntity, it is a human-palatable identifier for a
   *       user account. It is intended only for display, i.e., aiding the user in determining the
   *       difference between user accounts with similar displayNames. For example, "alexm",
   *       "alex.p.mueller@example.com" or "+14255551234".
   *       <ul>
   *         <li>The Relying Party MAY let the user choose this value. The Relying Party SHOULD
   *             perform enforcement, as prescribed in Section 3.4.3 of [RFC8265] for the
   *             UsernameCasePreserved Profile of the PRECIS IdentifierClass [RFC8264], when setting
   *             name's value, or displaying the value to the user.
   *         <li>Clients SHOULD perform enforcement, as prescribed in Section 3.4.3 of [RFC8265] for
   *             the UsernameCasePreserved Profile of the PRECIS IdentifierClass [RFC8264], on
   *             name's value prior to displaying the value to the user or including the value as a
   *             parameter of the authenticatorMakeCredential operation.
   *       </ul>
   * </ul>
   *
   * <p>When clients, client platforms, or authenticators display a name's value, they should always
   * use UI elements to provide a clear boundary around the displayed value, and not allow overflow
   * into other elements.
   *
   * <p>Authenticators MUST accept and store a 64-byte minimum length for a name member’s value.
   * Authenticators MAY truncate a name member’s value to a length equal to or greater than 64
   * bytes.
   *
   * @see <a href="https://tools.ietf.org/html/rfc8264">RFC 8264</a>
   * @see <a href="https://tools.ietf.org/html/rfc8265">RFC 8265</a>
   */
  String getName();

  /**
   * A serialized URL which resolves to an image associated with the entity.
   *
   * <p>For example, this could be a user's avatar or a Relying Party's logo. This URL MUST be an a
   * priori authenticated URL. Authenticators MUST accept and store a 128-byte minimum length for an
   * icon member's value. Authenticators MAY ignore an icon member's value if its length is greater
   * than 128 bytes. The URL's scheme MAY be "data" to avoid fetches of the URL, at the cost of
   * needing more storage.
   *
   * @deprecated The <code>icon</code> field has been removed from WebAuthn Level 2. This method
   *     will be removed in the next major version of this library.
   */
  @Deprecated
  Optional<URL> getIcon(); // TODO v2.0: delete this
}
