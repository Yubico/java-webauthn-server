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
import com.yubico.webauthn.data.exception.Base64UrlException;
import java.io.IOException;
import java.util.Optional;
import lombok.Builder;
import lombok.Getter;
import lombok.NonNull;
import lombok.Value;

/**
 * Represents an authenticator's response to a client’s request for generation of a new
 * authentication assertion given the WebAuthn Relying Party's {@linkplain
 * PublicKeyCredentialRequestOptions#getChallenge()} challenge} and OPTIONAL {@linkplain
 * PublicKeyCredentialRequestOptions#getAllowCredentials()} list of credentials} it is aware of.
 * This response contains a cryptographic {@linkplain #signature} proving possession of the
 * credential private key, and optionally evidence of user consent to a specific transaction.
 *
 * @see <a
 *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#authenticatorassertionresponse">§5.2.2.
 *     Web Authentication Assertion (interface AuthenticatorAssertionResponse) </a>
 */
@Value
public class AuthenticatorAssertionResponse implements AuthenticatorResponse {

  @NonNull
  @Getter(onMethod = @__({@Override}))
  private final ByteArray authenticatorData;

  @NonNull
  @Getter(onMethod = @__({@Override}))
  private final ByteArray clientDataJSON;

  /**
   * The raw signature returned from the authenticator. See <a
   * href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-op-get-assertion">§6.3.3 The
   * authenticatorGetAssertion Operation</a>.
   */
  @NonNull private final ByteArray signature;

  /**
   * The user handle returned from the authenticator, or empty if the authenticator did not return a
   * user handle. See <a
   * href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-op-get-assertion">§6.3.3 The
   * authenticatorGetAssertion Operation</a>.
   */
  private final ByteArray userHandle;

  @NonNull
  @Getter(onMethod = @__({@Override}))
  private final transient CollectedClientData clientData;

  @JsonCreator
  @Builder(toBuilder = true)
  private AuthenticatorAssertionResponse(
      @NonNull @JsonProperty("authenticatorData") final ByteArray authenticatorData,
      @NonNull @JsonProperty("clientDataJSON") final ByteArray clientDataJSON,
      @NonNull @JsonProperty("signature") final ByteArray signature,
      @JsonProperty("userHandle") final ByteArray userHandle)
      throws IOException, Base64UrlException {
    this.authenticatorData = authenticatorData;
    this.clientDataJSON = clientDataJSON;
    this.signature = signature;
    this.userHandle = userHandle;
    this.clientData = new CollectedClientData(this.clientDataJSON);
  }

  /**
   * The user handle returned from the authenticator, or empty if the authenticator did not return a
   * user handle. See <a
   * href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-op-get-assertion">§6.3.3 The
   * authenticatorGetAssertion Operation</a>.
   */
  public Optional<ByteArray> getUserHandle() {
    return Optional.ofNullable(userHandle);
  }

  public static AuthenticatorAssertionResponseBuilder.MandatoryStages builder() {
    return new AuthenticatorAssertionResponseBuilder.MandatoryStages();
  }

  public static class AuthenticatorAssertionResponseBuilder {
    private ByteArray userHandle = null;

    public static class MandatoryStages {
      private final AuthenticatorAssertionResponseBuilder builder =
          new AuthenticatorAssertionResponseBuilder();

      /**
       * {@link AuthenticatorAssertionResponseBuilder#authenticatorData(ByteArray)
       * authenticatorData} is a required parameter.
       *
       * @see AuthenticatorAssertionResponseBuilder#authenticatorData(ByteArray)
       */
      public Step2 authenticatorData(ByteArray authenticatorData) {
        builder.authenticatorData(authenticatorData);
        return new Step2();
      }

      public class Step2 {
        /**
         * {@link AuthenticatorAssertionResponseBuilder#clientDataJSON(ByteArray) clientDataJSON} is
         * a required parameter.
         *
         * @see AuthenticatorAssertionResponseBuilder#clientDataJSON(ByteArray)
         */
        public Step3 clientDataJSON(ByteArray clientDataJSON) {
          builder.clientDataJSON(clientDataJSON);
          return new Step3();
        }
      }

      public class Step3 {
        /**
         * {@link AuthenticatorAssertionResponseBuilder#signature(ByteArray) signature} is a
         * required parameter.
         *
         * @see AuthenticatorAssertionResponseBuilder#signature(ByteArray)
         */
        public AuthenticatorAssertionResponseBuilder signature(ByteArray signature) {
          return builder.signature(signature);
        }
      }
    }

    /**
     * The user handle returned from the authenticator, or empty if the authenticator did not return
     * a user handle. See <a
     * href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-op-get-assertion">§6.3.3 The
     * authenticatorGetAssertion Operation</a>.
     */
    public AuthenticatorAssertionResponseBuilder userHandle(
        @NonNull Optional<ByteArray> userHandle) {
      return this.userHandle(userHandle.orElse(null));
    }

    /**
     * The user handle returned from the authenticator, or empty if the authenticator did not return
     * a user handle. See <a
     * href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-op-get-assertion">§6.3.3 The
     * authenticatorGetAssertion Operation</a>.
     */
    public AuthenticatorAssertionResponseBuilder userHandle(ByteArray userHandle) {
      this.userHandle = userHandle;
      return this;
    }
  }
}
