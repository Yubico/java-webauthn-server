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

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.net.URL;
import java.util.Optional;
import lombok.Builder;
import lombok.Getter;
import lombok.NonNull;
import lombok.Value;

/**
 * Describes a user account, with which public key credentials can be associated.
 *
 * @see <a
 *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#dictdef-publickeycredentialuserentity">§5.4.3.
 *     User Account Parameters for Credential Generation (dictionary PublicKeyCredentialUserEntity)
 *     </a>
 */
@Value
@Builder(toBuilder = true)
public class UserIdentity implements PublicKeyCredentialEntity {

  /**
   * A human-palatable identifier for a user account. It is intended only for display, i.e., aiding
   * the user in determining the difference between user accounts with similar {@link
   * #displayName}s.
   *
   * <p>For example: "alexm", "alex.p.mueller@example.com" or "+14255551234".
   */
  @NonNull
  @Getter(onMethod = @__({@Override}))
  private final String name;

  /**
   * A human-palatable name for the user account, intended only for display. For example, "Alex P.
   * Müller" or "田中 倫". The Relying Party SHOULD let the user choose this, and SHOULD NOT restrict
   * the choice more than necessary.
   *
   * <ul>
   *   <li>Relying Parties SHOULD perform enforcement, as prescribed in Section 2.3 of [RFC8266] for
   *       the Nickname Profile of the PRECIS FreeformClass [RFC8264], when setting {@link
   *       #displayName}'s value, or displaying the value to the user.
   *   <li>Clients SHOULD perform enforcement, as prescribed in Section 2.3 of [RFC8266] for the
   *       Nickname Profile of the PRECIS FreeformClass [RFC8264], on {@link #displayName}'s value
   *       prior to displaying the value to the user or including the value as a parameter of the
   *       <code>authenticatorMakeCredential</code> operation.
   * </ul>
   *
   * <p>When clients, client platforms, or authenticators display a {@link #displayName}'s value,
   * they should always use UI elements to provide a clear boundary around the displayed value, and
   * not allow overflow into other elements.
   *
   * <p>Authenticators MUST accept and store a 64-byte minimum length for a {@link #displayName}
   * member's value. Authenticators MAY truncate a {@link #displayName} member's value to a length
   * equal to or greater than 64 bytes.
   *
   * @see <a href="https://tools.ietf.org/html/rfc8264">RFC 8264</a>
   * @see <a href="https://tools.ietf.org/html/rfc8266">RFC 8266</a>
   */
  @NonNull private final String displayName;

  /**
   * The <a href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#user-handle">user handle</a>
   * for the account, specified by the Relying Party.
   *
   * <p>A user handle is an opaque byte sequence with a maximum size of 64 bytes. User handles are
   * not meant to be displayed to users. The user handle SHOULD NOT contain personally identifying
   * information about the user, such as a username or e-mail address; see <a
   * href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-user-handle-privacy">§14.9 User
   * Handle Contents</a> for details.
   *
   * <p>To ensure secure operation, authentication and authorization decisions MUST be made on the
   * basis of this {@link #id} member, not the {@link #displayName} nor {@link #name} members. See
   * <a href="https://tools.ietf.org/html/rfc8266#section-6.1">Section 6.1 of RFC 8266</a>.
   *
   * <p>An authenticator will never contain more than one credential for a given Relying Party under
   * the same user handle.
   */
  @NonNull private final ByteArray id;

  /**
   * A URL which resolves to an image associated with the entity. For example, this could be the
   * user’s avatar.
   *
   * <p>This URL MUST be an a priori authenticated URL. Authenticators MUST accept and store a
   * 128-byte minimum length for an icon member’s value. Authenticators MAY ignore an icon member’s
   * value if its length is greater than 128 bytes. The URL’s scheme MAY be "data" to avoid fetches
   * of the URL, at the cost of needing more storage.
   *
   * @deprecated The <code>icon</code> property has been removed from WebAuthn Level 2. This field
   *     will be removed in the next major version of the library.
   */
  @Deprecated private final URL icon; // TODO v2.0: delete this

  @JsonCreator
  private UserIdentity(
      @NonNull @JsonProperty("name") String name,
      @NonNull @JsonProperty("displayName") String displayName,
      @NonNull @JsonProperty("id") ByteArray id,
      @JsonProperty("icon") URL icon) {
    this.name = name;
    this.displayName = displayName;
    this.id = id;
    this.icon = icon;
  }

  public static UserIdentityBuilder.MandatoryStages builder() {
    return new UserIdentityBuilder.MandatoryStages();
  }

  public static class UserIdentityBuilder {
    private URL icon = null;

    public static class MandatoryStages {
      private UserIdentityBuilder builder = new UserIdentityBuilder();

      /**
       * {@link UserIdentityBuilder#name(String) name} is a required parameter.
       *
       * @see UserIdentityBuilder#name(String)
       */
      public Step2 name(String name) {
        builder.name(name);
        return new Step2();
      }

      public class Step2 {
        /**
         * {@link UserIdentityBuilder#displayName(String) displayName} is a required parameter.
         *
         * @see UserIdentityBuilder#displayName(String)
         */
        public Step3 displayName(String displayName) {
          builder.displayName(displayName);
          return new Step3();
        }
      }

      public class Step3 {
        /**
         * {@link UserIdentityBuilder#id(ByteArray) id} is a required parameter.
         *
         * @see UserIdentityBuilder#id(ByteArray)
         */
        public UserIdentityBuilder id(ByteArray id) {
          return builder.id(id);
        }
      }
    }

    /**
     * A URL which resolves to an image associated with the entity. For example, this could be the
     * user’s avatar.
     *
     * <p>This URL MUST be an a priori authenticated URL. Authenticators MUST accept and store a
     * 128-byte minimum length for an icon member’s value. Authenticators MAY ignore an icon
     * member’s value if its length is greater than 128 bytes. The URL’s scheme MAY be "data" to
     * avoid fetches of the URL, at the cost of needing more storage.
     *
     * @deprecated The <code>icon</code> property has been removed from WebAuthn Level 2. This
     *     method will be removed in the next major version of the library.
     */
    @Deprecated
    public UserIdentityBuilder icon(@NonNull Optional<URL> icon) {
      return this.icon(icon.orElse(null));
    }

    /**
     * A URL which resolves to an image associated with the entity. For example, this could be the
     * user’s avatar.
     *
     * <p>This URL MUST be an a priori authenticated URL. Authenticators MUST accept and store a
     * 128-byte minimum length for an icon member’s value. Authenticators MAY ignore an icon
     * member’s value if its length is greater than 128 bytes. The URL’s scheme MAY be "data" to
     * avoid fetches of the URL, at the cost of needing more storage.
     *
     * @deprecated The <code>icon</code> property has been removed from WebAuthn Level 2. This
     *     method will be removed in the next major version of the library.
     */
    @Deprecated
    public UserIdentityBuilder icon(URL icon) {
      this.icon = icon;
      return this;
    }
  }

  /**
   * @deprecated The <code>icon</code> property has been removed from WebAuthn Level 2. This method
   *     will be removed in the next major version of the library.
   */
  @Deprecated
  @Override
  public Optional<URL> getIcon() {
    return Optional.ofNullable(icon);
  }
}
