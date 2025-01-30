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
import com.fasterxml.jackson.annotation.JsonValue;
import com.yubico.webauthn.RelyingParty.RelyingPartyBuilder;
import com.yubico.webauthn.StartAssertionOptions;
import com.yubico.webauthn.StartAssertionOptions.StartAssertionOptionsBuilder;
import com.yubico.webauthn.StartRegistrationOptions;
import com.yubico.webauthn.StartRegistrationOptions.StartRegistrationOptionsBuilder;
import com.yubico.webauthn.attestation.AttestationTrustSource;
import java.util.stream.Stream;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.NonNull;
import lombok.Value;

/**
 * Hints to guide the user agent in interacting with the user.
 *
 * <p>For example, the {@link PublicKeyCredentialHint#SECURITY_KEY} hint may be used to ask the
 * client to emphasize the option of using an external security key, or the {@link
 * PublicKeyCredentialHint#CLIENT_DEVICE} hint may be used to ask the client to emphasize the option
 * of using a built-in passkey provider.
 *
 * <p>These hints are not requirements, and do not bind the user-agent, but may guide it in
 * providing the best experience by using contextual information about the request.
 *
 * @see StartRegistrationOptions#getHints()
 * @see StartAssertionOptions#getHints()
 * @see <a
 *     href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-publickeycredentialcreationoptions-hints">PublicKeyCredentialCreationOptions.hints</a>
 * @see <a
 *     href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-publickeycredentialrequestoptions-hints">PublicKeyCredentialRequestOptions.hints</a>
 * @see <a
 *     href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#enumdef-publickeycredentialhints">§5.8.7.
 *     User-agent Hints Enumeration (enum PublicKeyCredentialHints)</a>
 */
@Value
@AllArgsConstructor(access = AccessLevel.PRIVATE)
public class PublicKeyCredentialHint {

  @JsonValue @NonNull private final String value;

  /**
   * Indicates that the application believes that users will satisfy this request with a physical
   * security key.
   *
   * <p>For example, an enterprise application may set this hint if they have issued security keys
   * to their employees and will only accept those authenticators for registration and
   * authentication. In that case, the application should probably also set {@link
   * RelyingPartyBuilder#attestationTrustSource(AttestationTrustSource) attestationTrustSource} and
   * set {@link RelyingPartyBuilder#allowUntrustedAttestation(boolean) allowUntrustedAttestation} to
   * <code>false</code>. See also the <a
   * href="https://developers.yubico.com/java-webauthn-server/webauthn-server-attestation/"><code>
   * webauthn-server-attestation</code> module</a>.
   *
   * <p>For compatibility with older user agents, when this hint is used in {@link
   * StartRegistrationOptions}, the <code>
   * {@link StartRegistrationOptionsBuilder#authenticatorSelection(AuthenticatorSelectionCriteria) authenticatorSelection}.{@link AuthenticatorSelectionCriteria.AuthenticatorSelectionCriteriaBuilder#authenticatorAttachment(AuthenticatorAttachment) authenticatorAttachment}
   * </code> parameter SHOULD be set to {@link AuthenticatorAttachment#CROSS_PLATFORM}.
   *
   * @see StartRegistrationOptionsBuilder#hints(PublicKeyCredentialHint...)
   * @see StartAssertionOptionsBuilder#hints(PublicKeyCredentialHint...)
   * @see <a
   *     href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-publickeycredentialhints-security-key">
   *     <code>security-key</code> in §5.8.7. User-agent Hints Enumeration (enum
   *     PublicKeyCredentialHints) </a>
   * @see <a
   *     href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#enumdef-publickeycredentialhints">§5.8.7.
   *     User-agent Hints Enumeration (enum PublicKeyCredentialHints)</a>
   */
  public static final PublicKeyCredentialHint SECURITY_KEY =
      new PublicKeyCredentialHint("security-key");

  /**
   * Indicates that the application believes that users will satisfy this request with an
   * authenticator built into the client device.
   *
   * <p>For compatibility with older user agents, when this hint is used in {@link
   * StartRegistrationOptions}, the <code>
   * {@link StartRegistrationOptionsBuilder#authenticatorSelection(AuthenticatorSelectionCriteria) authenticatorSelection}.{@link AuthenticatorSelectionCriteria.AuthenticatorSelectionCriteriaBuilder#authenticatorAttachment(AuthenticatorAttachment) authenticatorAttachment}
   * </code> parameter SHOULD be set to {@link AuthenticatorAttachment#PLATFORM}.
   *
   * @see StartRegistrationOptionsBuilder#hints(PublicKeyCredentialHint...)
   * @see StartAssertionOptionsBuilder#hints(PublicKeyCredentialHint...)
   * @see <a
   *     href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-publickeycredentialhints-client-device">
   *     <code>client-device</code> in §5.8.7. User-agent Hints Enumeration (enum
   *     PublicKeyCredentialHints) </a>
   * @see <a
   *     href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#enumdef-publickeycredentialhints">§5.8.7.
   *     User-agent Hints Enumeration (enum PublicKeyCredentialHints)</a>
   */
  public static final PublicKeyCredentialHint CLIENT_DEVICE =
      new PublicKeyCredentialHint("client-device");

  /**
   * Indicates that the application believes that users will satisfy this request with
   * general-purpose authenticators such as smartphones. For example, a consumer application may
   * believe that only a small fraction of their customers possesses dedicated security keys. This
   * option also implies that the local platform authenticator should not be promoted in the UI.
   *
   * <p>For compatibility with older user agents, when this hint is used in {@link
   * StartRegistrationOptions}, the <code>
   * {@link StartRegistrationOptionsBuilder#authenticatorSelection(AuthenticatorSelectionCriteria) authenticatorSelection}.{@link AuthenticatorSelectionCriteria.AuthenticatorSelectionCriteriaBuilder#authenticatorAttachment(AuthenticatorAttachment) authenticatorAttachment}
   * </code> parameter SHOULD be set to {@link AuthenticatorAttachment#CROSS_PLATFORM}.
   *
   * @see StartRegistrationOptionsBuilder#hints(PublicKeyCredentialHint...)
   * @see StartAssertionOptionsBuilder#hints(PublicKeyCredentialHint...)
   * @see <a
   *     href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-publickeycredentialhints-hybrid">
   *     <code>hybrid</code> in §5.8.7. User-agent Hints Enumeration (enum PublicKeyCredentialHints)
   *     </a>
   * @see <a
   *     href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#enumdef-publickeycredentialhints">§5.8.7.
   *     User-agent Hints Enumeration (enum PublicKeyCredentialHints)</a>
   */
  public static final PublicKeyCredentialHint HYBRID = new PublicKeyCredentialHint("hybrid");

  /**
   * @return An array containing all predefined values of {@link PublicKeyCredentialHint} known by
   *     this implementation.
   */
  public static PublicKeyCredentialHint[] values() {
    return new PublicKeyCredentialHint[] {SECURITY_KEY, CLIENT_DEVICE, HYBRID};
  }

  /**
   * @return If <code>value</code> is the same as that of any of {@link #SECURITY_KEY}, {@link
   *     #CLIENT_DEVICE} or {@link #HYBRID}, returns that constant instance. Otherwise returns a new
   *     instance containing <code>value</code>.
   * @see #valueOf(String)
   */
  @JsonCreator
  public static PublicKeyCredentialHint of(@NonNull String value) {
    return Stream.of(values())
        .filter(v -> v.getValue().equals(value))
        .findAny()
        .orElseGet(() -> new PublicKeyCredentialHint(value));
  }

  /**
   * @return If <code>name</code> equals <code>"SECURITY_KEY"</code>, <code>"CLIENT_DEVICE"</code>
   *     or <code>"HYBRID"</code>, returns the constant by that name.
   * @throws IllegalArgumentException if <code>name</code> is anything else.
   * @see #of(String)
   */
  public static PublicKeyCredentialHint valueOf(String name) {
    switch (name) {
      case "SECURITY_KEY":
        return SECURITY_KEY;
      case "CLIENT_DEVICE":
        return CLIENT_DEVICE;
      case "HYBRID":
        return HYBRID;
      default:
        throw new IllegalArgumentException(
            "No constant com.yubico.webauthn.data.PublicKeyCredentialHint." + name);
    }
  }
}
