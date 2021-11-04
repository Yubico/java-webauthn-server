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
import com.fasterxml.jackson.core.type.TypeReference;
import com.yubico.internal.util.JacksonCodecs;
import java.io.IOException;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.NonNull;
import lombok.Value;

/**
 * The PublicKeyCredential interface inherits from Credential <a
 * href="https://www.w3.org/TR/credential-management-1/">[CREDENTIAL-MANAGEMENT-1]</a>, and contains
 * the attributes that are returned to the caller when a new credential is created, or a new
 * assertion is requested.
 *
 * @see <a href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#iface-pkcredential">§5.1.
 *     PublicKeyCredential Interface</a>
 */
@Value
@Builder(toBuilder = true)
public class PublicKeyCredential<
    A extends AuthenticatorResponse, B extends ClientExtensionOutputs> {

  /**
   * The raw Credential ID of this credential, corresponding to the <code>rawId</code> attribute in
   * the WebAuthn API.
   */
  @NonNull private final ByteArray id;

  /**
   * The authenticator's response to the client’s request to either create a public key credential,
   * or generate an authentication assertion.
   *
   * <p>If the {@link PublicKeyCredential} was created in response to <code>
   * navigator.credentials.create()</code>, this attribute’s value will be an {@link
   * AuthenticatorAttestationResponse}, otherwise, the {@link PublicKeyCredential} was created in
   * response to <code>navigator.credentials.get()</code>, and this attribute’s value will be an
   * {@link AuthenticatorAssertionResponse}.
   */
  @NonNull private final A response;

  /**
   * A map containing extension identifier → client extension output entries produced by the
   * extension’s client extension processing.
   */
  @NonNull private final B clientExtensionResults;

  /** The {@link PublicKeyCredential}'s type value is the string "public-key". */
  @NonNull @Builder.Default
  private final PublicKeyCredentialType type = PublicKeyCredentialType.PUBLIC_KEY;

  @JsonCreator
  private PublicKeyCredential(
      @JsonProperty("id") ByteArray id,
      @JsonProperty("rawId") ByteArray rawId,
      @NonNull @JsonProperty("response") A response,
      @NonNull @JsonProperty("clientExtensionResults") B clientExtensionResults,
      @NonNull @JsonProperty("type") PublicKeyCredentialType type) {
    if (id == null && rawId == null) {
      throw new NullPointerException("At least one of \"id\" and \"rawId\" must be non-null.");
    }
    if (id != null && rawId != null && !id.equals(rawId)) {
      throw new IllegalArgumentException(
          String.format("\"id\" and \"rawId\" are not equal: %s != %s", id, rawId));
    }

    this.id = id == null ? rawId : id;
    this.response = response;
    this.clientExtensionResults = clientExtensionResults;
    this.type = type;
  }

  private PublicKeyCredential(
      ByteArray id,
      @NonNull A response,
      @NonNull B clientExtensionResults,
      @NonNull PublicKeyCredentialType type) {
    this(id, null, response, clientExtensionResults, type);
  }

  public static <A extends AuthenticatorResponse, B extends ClientExtensionOutputs>
      PublicKeyCredentialBuilder<A, B>.MandatoryStages builder() {
    return new PublicKeyCredentialBuilder<A, B>().start();
  }

  public static class PublicKeyCredentialBuilder<
      A extends AuthenticatorResponse, B extends ClientExtensionOutputs> {
    private MandatoryStages start() {
      return new MandatoryStages(this);
    }

    @AllArgsConstructor
    public class MandatoryStages {
      private final PublicKeyCredentialBuilder<A, B> builder;

      /**
       * {@link PublicKeyCredentialBuilder#id(ByteArray) id} is a required parameter.
       *
       * @see PublicKeyCredentialBuilder#id(ByteArray)
       */
      public Step2 id(ByteArray id) {
        builder.id(id);
        return new Step2();
      }

      public class Step2 {
        /**
         * {@link PublicKeyCredentialBuilder#response(AuthenticatorResponse) response} is a required
         * parameter.
         *
         * @see PublicKeyCredentialBuilder#response(AuthenticatorResponse)
         */
        public Step3 response(A response) {
          builder.response(response);
          return new Step3();
        }
      }

      public class Step3 {
        /**
         * {@link PublicKeyCredentialBuilder#clientExtensionResults(ClientExtensionOutputs)
         * clientExtensionResults} is a required parameter.
         *
         * @see PublicKeyCredentialBuilder#clientExtensionResults(ClientExtensionOutputs)
         */
        public PublicKeyCredentialBuilder<A, B> clientExtensionResults(B clientExtensionResults) {
          return builder.clientExtensionResults(clientExtensionResults);
        }
      }
    }
  }

  /**
   * Parse a {@link PublicKeyCredential} object from JSON.
   *
   * <p>The <code>json</code> should be of the following format:
   *
   * <pre>
   * {
   *   "id": "(resp.id)",
   *   "response": {
   *     "attestationObject": "(Base64Url encoded resp.attestationObject)",
   *     "clientDataJSON": "(Base64Url encoded resp.clientDataJSON)"
   *   },
   *   "clientExtensionResults": { (resp.getClientExtensionResults()) },
   *   "type": "public-key"
   * }
   * </pre>
   *
   * <dl>
   *   <dt>resp:
   *   <dd>The <a
   *       href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#iface-pkcredential">PublicKeyCredential</a>
   *       object returned from a registration ceremony.
   *   <dt>id:
   *   <dd>The string value of <code>resp.id</code>
   *   <dt>response.attestationObject:
   *   <dd>The value of <code>resp.attestationObject</code>, Base64Url encoded as a string
   *   <dt>response.clientDataJSON:
   *   <dd>The value of <code>resp.clientDataJSON</code>, Base64Url encoded as a string
   *   <dt>clientExtensionResults:
   *   <dd>The return value of <code>resp.getClientExtensionResults()</code>
   *   <dt>type:
   *   <dd>The literal string value <code>"public-key"</code>
   * </dl>
   *
   * @param json a JSON string of the above format
   * @throws IOException if the <code>json</code> is invalid or cannot be decoded as a {@link
   *     PublicKeyCredential}
   */
  public static PublicKeyCredential<
          AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs>
      parseRegistrationResponseJson(String json) throws IOException {
    return JacksonCodecs.json()
        .readValue(
            json,
            new TypeReference<
                PublicKeyCredential<
                    AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs>>() {});
  }

  /**
   * Parse a {@link PublicKeyCredential} object from JSON.
   *
   * <p>The <code>json</code> should be of the following format:
   *
   * <pre>
   * {
   *   "id": "(resp.id)",
   *   "response": {
   *     "authenticatorData": "(Base64Url encoded resp.authenticatorData)",
   *     "signature": "(Base64Url encoded resp.signature)",
   *     "clientDataJSON": "(Base64Url encoded resp.clientDataJSON)",
   *     "userHandle": "(null, undefined or Base64Url encoded resp.userHandle)"
   *   },
   *   "clientExtensionResults": { (resp.getClientExtensionResults()) },
   *   "type": "public-key"
   * }
   * </pre>
   *
   * <dl>
   *   <dt>resp:
   *   <dd>The <a
   *       href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#iface-pkcredential">PublicKeyCredential</a>
   *       object returned from an authentication ceremony.
   *   <dt>id:
   *   <dd>The string value of <code>resp.id</code>
   *   <dt>response.authenticatorData:
   *   <dd>The value of <code>resp.authenticatorData</code>, Base64Url encoded as a string
   *   <dt>response.signature:
   *   <dd>The value of <code>resp.signature</code>, Base64Url encoded as a string
   *   <dt>response.clientDataJSON:
   *   <dd>The value of <code>resp.clientDataJSON</code>, Base64Url encoded as a string
   *   <dt>response.userHandle:
   *   <dd>The value of <code>resp.userHandle</code> Base64Url encoded as a string if present,
   *       otherwise <code>null</code> or <code>undefined</code>
   *   <dt>clientExtensionResults:
   *   <dd>The return value of <code>resp.getClientExtensionResults()</code>
   *   <dt>type:
   *   <dd>The literal string value <code>"public-key"</code>
   * </dl>
   *
   * @param json a JSON string of the above format
   * @throws IOException if the <code>json</code> is invalid or cannot be decoded as a {@link
   *     PublicKeyCredential}
   */
  public static PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs>
      parseAssertionResponseJson(String json) throws IOException {
    return JacksonCodecs.json()
        .readValue(
            json,
            new TypeReference<
                PublicKeyCredential<
                    AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs>>() {});
  }
}
