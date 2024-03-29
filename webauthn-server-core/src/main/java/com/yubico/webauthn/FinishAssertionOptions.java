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

package com.yubico.webauthn;

import com.yubico.webauthn.data.AuthenticatorAssertionResponse;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.ClientAssertionExtensionOutputs;
import com.yubico.webauthn.data.CollectedClientData;
import com.yubico.webauthn.data.PublicKeyCredential;
import java.util.Optional;
import java.util.Set;
import lombok.Builder;
import lombok.NonNull;
import lombok.Value;

/** Parameters for {@link RelyingParty#finishAssertion(FinishAssertionOptions)}. */
@Value
@Builder(toBuilder = true)
public class FinishAssertionOptions {

  /** The request that the {@link #getResponse() response} is a response to. */
  @NonNull private final AssertionRequest request;

  /**
   * The client's response to the {@link #getRequest() request}.
   *
   * @see <a
   *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-getAssertion">navigator.credentials.get()</a>
   */
  @NonNull
  private final PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs>
      response;

  /**
   * The <a href="https://tools.ietf.org/html/rfc8471#section-3.2">token binding ID</a> of the
   * connection to the client, if any.
   *
   * @see <a href="https://tools.ietf.org/html/rfc8471">The Token Binding Protocol Version 1.0</a>
   */
  private final ByteArray callerTokenBindingId;

  /**
   * EXPERIMENTAL FEATURE:
   *
   * <p>If set to <code>false</code> (the default), the <code>"type"</code> property in the <a
   * href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#dictionary-client-data">collected
   * client data</a> of the assertion will be verified to equal <code>"webauthn.get"</code>.
   *
   * <p>If set to <code>true</code>, it will instead be verified to equal <code>"payment.get"</code>
   * .
   *
   * <p>NOTE: If you're using <a
   * href="https://www.w3.org/TR/2023/CR-secure-payment-confirmation-20230615/">Secure Payment
   * Confirmation</a> (SPC), you likely also need to relax the origin validation logic. Right now
   * this library only supports matching against a finite {@link Set} of acceptable origins. If
   * necessary, your application may validate the origin externally (see {@link
   * PublicKeyCredential#getResponse()}, {@link AuthenticatorAssertionResponse#getClientData()} and
   * {@link CollectedClientData#getOrigin()}) and construct a new {@link RelyingParty} instance for
   * each SPC response, setting the {@link RelyingParty.RelyingPartyBuilder#origins(Set) origins}
   * setting on that instance to contain the pre-validated origin value.
   *
   * <p>Better support for relaxing origin validation may be added as the feature matures.
   *
   * @deprecated EXPERIMENTAL: This is an experimental feature. It is likely to change or be deleted
   *     before reaching a mature release.
   * @see <a href="https://www.w3.org/TR/2023/CR-secure-payment-confirmation-20230615/">Secure
   *     Payment Confirmation</a>
   * @see <a
   *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#dictionary-client-data">5.8.1.
   *     Client Data Used in WebAuthn Signatures (dictionary CollectedClientData)</a>
   * @see RelyingParty.RelyingPartyBuilder#origins(Set)
   * @see CollectedClientData
   * @see CollectedClientData#getOrigin()
   */
  @Deprecated @Builder.Default private final boolean isSecurePaymentConfirmation = false;

  /**
   * The <a href="https://tools.ietf.org/html/rfc8471#section-3.2">token binding ID</a> of the
   * connection to the client, if any.
   *
   * @see <a href="https://tools.ietf.org/html/rfc8471">The Token Binding Protocol Version 1.0</a>
   */
  public Optional<ByteArray> getCallerTokenBindingId() {
    return Optional.ofNullable(callerTokenBindingId);
  }

  public static FinishAssertionOptionsBuilder.MandatoryStages builder() {
    return new FinishAssertionOptionsBuilder.MandatoryStages();
  }

  public static class FinishAssertionOptionsBuilder {
    private ByteArray callerTokenBindingId = null;

    public static class MandatoryStages {
      private final FinishAssertionOptionsBuilder builder = new FinishAssertionOptionsBuilder();

      /**
       * {@link FinishAssertionOptionsBuilder#request(AssertionRequest) request} is a required
       * parameter.
       *
       * @see FinishAssertionOptionsBuilder#request(AssertionRequest)
       */
      public Step2 request(AssertionRequest request) {
        builder.request(request);
        return new Step2();
      }

      public class Step2 {
        /**
         * {@link FinishAssertionOptionsBuilder#response(PublicKeyCredential) response} is a
         * required parameter.
         *
         * @see FinishAssertionOptionsBuilder#response(PublicKeyCredential)
         */
        public FinishAssertionOptionsBuilder response(
            PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs>
                response) {
          return builder.response(response);
        }
      }
    }

    /**
     * The <a href="https://tools.ietf.org/html/rfc8471#section-3.2">token binding ID</a> of the
     * connection to the client, if any.
     *
     * @see <a href="https://tools.ietf.org/html/rfc8471">The Token Binding Protocol Version 1.0</a>
     */
    public FinishAssertionOptionsBuilder callerTokenBindingId(
        @NonNull Optional<ByteArray> callerTokenBindingId) {
      this.callerTokenBindingId = callerTokenBindingId.orElse(null);
      return this;
    }

    /**
     * The <a href="https://tools.ietf.org/html/rfc8471#section-3.2">token binding ID</a> of the
     * connection to the client, if any.
     *
     * @see <a href="https://tools.ietf.org/html/rfc8471">The Token Binding Protocol Version 1.0</a>
     */
    public FinishAssertionOptionsBuilder callerTokenBindingId(
        @NonNull ByteArray callerTokenBindingId) {
      return this.callerTokenBindingId(Optional.of(callerTokenBindingId));
    }
  }
}
