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

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.yubico.internal.util.JacksonCodecs;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredentialRequestOptions;
import java.util.Optional;
import lombok.Builder;
import lombok.NonNull;
import lombok.Value;

/**
 * A combination of a {@link PublicKeyCredentialRequestOptions} and, optionally, a {@link
 * #getUsername() username}.
 */
@Value
@Builder(toBuilder = true)
public class AssertionRequest {

  /**
   * An object that can be serialized to JSON and passed as the <code>publicKey</code> argument to
   * <code>navigator.credentials.get()</code>.
   */
  @NonNull private final PublicKeyCredentialRequestOptions publicKeyCredentialRequestOptions;

  /**
   * The username of the user to authenticate, if the user has already been identified.
   *
   * <p>If this is absent, this indicates that this is a request for an assertion by a <a
   * href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#client-side-discoverable-public-key-credential-source">client-side-resident
   * credential</a>, and identification of the user has been deferred until the response is
   * received.
   */
  private final String username;

  @JsonCreator
  private AssertionRequest(
      @NonNull @JsonProperty("publicKeyCredentialRequestOptions")
          PublicKeyCredentialRequestOptions publicKeyCredentialRequestOptions,
      @JsonProperty("username") String username) {
    this.publicKeyCredentialRequestOptions = publicKeyCredentialRequestOptions;
    this.username = username;
  }

  /**
   * The username of the user to authenticate, if the user has already been identified.
   *
   * <p>If this is absent, this indicates that this is a request for an assertion by a <a
   * href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#client-side-discoverable-public-key-credential-source">client-side-resident
   * credential</a>, and identification of the user has been deferred until the response is
   * received.
   */
  public Optional<String> getUsername() {
    return Optional.ofNullable(username);
  }

  /**
   * Serialize this {@link AssertionRequest} value to JSON suitable for sending to the client.
   *
   * <p>This is an alias of <code>getPublicKeyCredentialRequestOptions().toCredentialsGetJson()
   * </code>.
   *
   * <p>Any {@link ByteArray} values in this data structure will be {@link ByteArray#getBase64Url()
   * Base64Url} encoded. Those values MUST be decoded into <code>BufferSource</code> values (such as
   * <code>Uint8Array</code>) on the client side before calling <code>navigator.credentials.get()
   * </code>.
   *
   * <p>After decoding binary values, the resulting JavaScript object is suitable for passing as an
   * argument to <code>navigator.credentials.get()</code>.
   *
   * @return a JSON value suitable for sending to the client and passing as an argument to <code>
   *     navigator.credentials.get()</code>, after decoding binary options from Base64Url strings.
   * @throws JsonProcessingException if JSON serialization fails.
   */
  public String toCredentialsGetJson() throws JsonProcessingException {
    return publicKeyCredentialRequestOptions.toCredentialsGetJson();
  }

  /**
   * Encode this {@link AssertionRequest} to JSON. The inverse of {@link #fromJson(String)}.
   *
   * <p>This method is suitable for encoding the {@link AssertionRequest} for temporary storage so
   * that it can later be passed as an argument to {@link
   * RelyingParty#finishAssertion(FinishAssertionOptions)}. The {@link #fromJson(String)} factory
   * function is guaranteed to restore an identical {@link AssertionRequest} instance.
   *
   * <p>Note that encoding might not be needed if you can simply keep the {@link AssertionRequest}
   * instance in server memory.
   *
   * @return this {@link AssertionRequest} encoded to JSON.
   * @throws JsonProcessingException
   */
  public String toJson() throws JsonProcessingException {
    return JacksonCodecs.json().writeValueAsString(this);
  }

  /**
   * Decode an {@link AssertionRequest} from JSON. The inverse of {@link #toJson()}.
   *
   * <p>If the JSON was generated by the {@link #toJson()} method, then {@link #fromJson(String)} in
   * the same library version guarantees to restore an identical {@link AssertionRequest} instance.
   * This is not guaranteed between different library versions.
   *
   * @return a {@link AssertionRequest} decoded from the input JSON.
   * @throws JsonProcessingException
   */
  public static AssertionRequest fromJson(String json) throws JsonProcessingException {
    return JacksonCodecs.json().readValue(json, AssertionRequest.class);
  }

  public static AssertionRequestBuilder.MandatoryStages builder() {
    return new AssertionRequestBuilder.MandatoryStages();
  }

  public static class AssertionRequestBuilder {
    private String username = null;

    public static class MandatoryStages {
      private final AssertionRequestBuilder builder = new AssertionRequestBuilder();

      /**
       * {@link
       * AssertionRequestBuilder#publicKeyCredentialRequestOptions(PublicKeyCredentialRequestOptions)
       * publicKeyCredentialRequestOptions} is a required parameter.
       *
       * @see
       *     AssertionRequestBuilder#publicKeyCredentialRequestOptions(PublicKeyCredentialRequestOptions)
       */
      public AssertionRequestBuilder publicKeyCredentialRequestOptions(
          PublicKeyCredentialRequestOptions publicKeyCredentialRequestOptions) {
        return builder.publicKeyCredentialRequestOptions(publicKeyCredentialRequestOptions);
      }
    }

    /**
     * The username of the user to authenticate, if the user has already been identified.
     *
     * <p>If this is absent, this indicates that this is a request for an assertion by a <a
     * href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#client-side-discoverable-public-key-credential-source">client-side-resident
     * credential</a>, and identification of the user has been deferred until the response is
     * received.
     */
    public AssertionRequestBuilder username(@NonNull Optional<String> username) {
      return this.username(username.orElse(null));
    }

    /**
     * The username of the user to authenticate, if the user has already been identified.
     *
     * <p>If this is absent, this indicates that this is a request for an assertion by a <a
     * href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#client-side-discoverable-public-key-credential-source">client-side-resident
     * credential</a>, and identification of the user has been deferred until the response is
     * received.
     */
    public AssertionRequestBuilder username(String username) {
      this.username = username;
      return this;
    }
  }
}
