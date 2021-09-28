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

import com.yubico.webauthn.data.AuthenticatorAttestationResponse;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.ClientRegistrationExtensionOutputs;
import com.yubico.webauthn.data.PublicKeyCredential;
import com.yubico.webauthn.data.PublicKeyCredentialCreationOptions;
import java.util.Optional;
import lombok.Builder;
import lombok.NonNull;
import lombok.Value;

/** Parameters for {@link RelyingParty#finishRegistration(FinishRegistrationOptions)}. */
@Value
@Builder(toBuilder = true)
public class FinishRegistrationOptions {

  /** The request that the {@link #getResponse() response} is a response to. */
  @NonNull private final PublicKeyCredentialCreationOptions request;

  /**
   * The client's response to the {@link #getRequest() request}.
   *
   * <p><a
   * href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-createCredential">navigator.credentials.create()</a>
   */
  @NonNull
  private final PublicKeyCredential<
          AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs>
      response;

  /**
   * The <a href="https://tools.ietf.org/html/rfc8471#section-3.2">token binding ID</a> of the
   * connection to the client, if any.
   *
   * @see <a href="https://tools.ietf.org/html/rfc8471">The Token Binding Protocol Version 1.0</a>
   */
  private final ByteArray callerTokenBindingId;

  /**
   * The <a href="https://tools.ietf.org/html/rfc8471#section-3.2">token binding ID</a> of the
   * connection to the client, if any.
   *
   * @see <a href="https://tools.ietf.org/html/rfc8471">The Token Binding Protocol Version 1.0</a>
   */
  public Optional<ByteArray> getCallerTokenBindingId() {
    return Optional.ofNullable(callerTokenBindingId);
  }

  public static FinishRegistrationOptionsBuilder.MandatoryStages builder() {
    return new FinishRegistrationOptionsBuilder.MandatoryStages();
  }

  public static class FinishRegistrationOptionsBuilder {
    private ByteArray callerTokenBindingId = null;

    public static class MandatoryStages {
      private final FinishRegistrationOptionsBuilder builder =
          new FinishRegistrationOptionsBuilder();

      /**
       * {@link FinishRegistrationOptionsBuilder#request(PublicKeyCredentialCreationOptions)
       * request} is a required parameter.
       *
       * @see FinishRegistrationOptionsBuilder#request(PublicKeyCredentialCreationOptions)
       */
      public Step2 request(PublicKeyCredentialCreationOptions request) {
        builder.request(request);
        return new Step2();
      }

      public class Step2 {
        /**
         * {@link FinishRegistrationOptionsBuilder#response(PublicKeyCredential) response} is a
         * required parameter.
         *
         * @see FinishRegistrationOptionsBuilder#response(PublicKeyCredential)
         */
        public FinishRegistrationOptionsBuilder response(
            PublicKeyCredential<
                    AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs>
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
    public FinishRegistrationOptionsBuilder callerTokenBindingId(
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
    public FinishRegistrationOptionsBuilder callerTokenBindingId(
        @NonNull ByteArray callerTokenBindingId) {
      return this.callerTokenBindingId(Optional.of(callerTokenBindingId));
    }
  }
}
