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
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.yubico.internal.util.CollectionUtil;
import com.yubico.internal.util.JacksonCodecs;
import java.util.List;
import java.util.Optional;
import lombok.Builder;
import lombok.NonNull;
import lombok.Value;

/**
 * The PublicKeyCredentialRequestOptions dictionary supplies get() with the data it needs to
 * generate an assertion.
 *
 * <p>Its `challenge` member must be present, while its other members are optional.
 *
 * @see <a
 *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#dictdef-publickeycredentialrequestoptions">§5.5.
 *     Options for Assertion Generation (dictionary PublicKeyCredentialRequestOptions) </a>
 */
@Value
@Builder(toBuilder = true)
public class PublicKeyCredentialRequestOptions {

  /**
   * A challenge that the selected authenticator signs, along with other data, when producing an
   * authentication assertion. See the <a
   * href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-cryptographic-challenges">§13.1
   * Cryptographic Challenges</a> security consideration.
   */
  @NonNull private final ByteArray challenge;

  /**
   * Specifies a time, in milliseconds, that the caller is willing to wait for the call to complete.
   *
   * <p>This is treated as a hint, and MAY be overridden by the client.
   */
  private final Long timeout;

  /**
   * Specifies the relying party identifier claimed by the caller.
   *
   * <p>If omitted, its value will be set by the client.
   */
  private final String rpId;

  /**
   * A list of {@link PublicKeyCredentialDescriptor} objects representing public key credentials
   * acceptable to the caller, in descending order of the caller’s preference (the first item in the
   * list is the most preferred credential, and so on down the list).
   */
  private final List<PublicKeyCredentialDescriptor> allowCredentials;

  /**
   * Describes the Relying Party's requirements regarding <a
   * href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#user-verification">user
   * verification</a> for the <code>navigator.credentials.get()</code> operation.
   *
   * <p>Eligible authenticators are filtered to only those capable of satisfying this requirement.
   */
  @NonNull @Builder.Default
  private final UserVerificationRequirement userVerification =
      UserVerificationRequirement.PREFERRED;

  /**
   * Additional parameters requesting additional processing by the client and authenticator.
   *
   * <p>For example, if transaction confirmation is sought from the user, then the prompt string
   * might be included as an extension.
   */
  @NonNull @Builder.Default
  private final AssertionExtensionInputs extensions = AssertionExtensionInputs.builder().build();

  @JsonCreator
  private PublicKeyCredentialRequestOptions(
      @NonNull @JsonProperty("challenge") ByteArray challenge,
      @JsonProperty("timeout") Long timeout,
      @JsonProperty("rpId") String rpId,
      @JsonProperty("allowCredentials") List<PublicKeyCredentialDescriptor> allowCredentials,
      @NonNull @JsonProperty("userVerification") UserVerificationRequirement userVerification,
      @NonNull @JsonProperty("extensions") AssertionExtensionInputs extensions) {
    this.challenge = challenge;
    this.timeout = timeout;
    this.rpId = rpId;
    this.allowCredentials =
        allowCredentials == null ? null : CollectionUtil.immutableList(allowCredentials);
    this.userVerification = userVerification;
    this.extensions = extensions;
  }

  public Optional<Long> getTimeout() {
    return Optional.ofNullable(timeout);
  }

  public Optional<List<PublicKeyCredentialDescriptor>> getAllowCredentials() {
    return Optional.ofNullable(allowCredentials);
  }

  /**
   * Serialize this {@link PublicKeyCredentialRequestOptions} value to JSON suitable for sending to
   * the client.
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
    ObjectMapper json = JacksonCodecs.json();
    ObjectNode result = json.createObjectNode();
    result.set("publicKey", json.valueToTree(this));
    return json.writeValueAsString(result);
  }

  public static PublicKeyCredentialRequestOptionsBuilder.MandatoryStages builder() {
    return new PublicKeyCredentialRequestOptionsBuilder.MandatoryStages();
  }

  public static class PublicKeyCredentialRequestOptionsBuilder {
    private Long timeout = null;
    private String rpId = null;
    private List<PublicKeyCredentialDescriptor> allowCredentials = null;

    public static class MandatoryStages {
      private PublicKeyCredentialRequestOptionsBuilder builder =
          new PublicKeyCredentialRequestOptionsBuilder();

      /**
       * {@link PublicKeyCredentialRequestOptionsBuilder#challenge(ByteArray) challenge} is a
       * required parameter.
       *
       * @see PublicKeyCredentialRequestOptionsBuilder#challenge(ByteArray)
       */
      public PublicKeyCredentialRequestOptionsBuilder challenge(ByteArray challenge) {
        return builder.challenge(challenge);
      }
    }

    /**
     * Specifies a time, in milliseconds, that the caller is willing to wait for the call to
     * complete.
     *
     * <p>This is treated as a hint, and MAY be overridden by the client.
     */
    public PublicKeyCredentialRequestOptionsBuilder timeout(@NonNull Optional<Long> timeout) {
      this.timeout = timeout.orElse(null);
      return this;
    }

    /*
     * Workaround, see: https://github.com/rzwitserloot/lombok/issues/2623#issuecomment-714816001
     * Consider reverting this workaround if Lombok fixes that issue.
     */
    private PublicKeyCredentialRequestOptionsBuilder timeout(Long timeout) {
      return this.timeout(Optional.ofNullable(timeout));
    }

    /**
     * Specifies a time, in milliseconds, that the caller is willing to wait for the call to
     * complete.
     *
     * <p>This is treated as a hint, and MAY be overridden by the client.
     */
    public PublicKeyCredentialRequestOptionsBuilder timeout(long timeout) {
      return this.timeout(Optional.of(timeout));
    }

    /**
     * Specifies the relying party identifier claimed by the caller.
     *
     * <p>If omitted, its value will be set by the client.
     */
    public PublicKeyCredentialRequestOptionsBuilder rpId(@NonNull Optional<String> rpId) {
      return this.rpId(rpId.orElse(null));
    }

    /**
     * Specifies the relying party identifier claimed by the caller.
     *
     * <p>If omitted, its value will be set by the client.
     */
    public PublicKeyCredentialRequestOptionsBuilder rpId(String rpId) {
      this.rpId = rpId;
      return this;
    }

    /**
     * A list of {@link PublicKeyCredentialDescriptor} objects representing public key credentials
     * acceptable to the caller, in descending order of the caller’s preference (the first item in
     * the list is the most preferred credential, and so on down the list).
     */
    public PublicKeyCredentialRequestOptionsBuilder allowCredentials(
        @NonNull Optional<List<PublicKeyCredentialDescriptor>> allowCredentials) {
      return this.allowCredentials(allowCredentials.orElse(null));
    }

    /**
     * A list of {@link PublicKeyCredentialDescriptor} objects representing public key credentials
     * acceptable to the caller, in descending order of the caller’s preference (the first item in
     * the list is the most preferred credential, and so on down the list).
     */
    public PublicKeyCredentialRequestOptionsBuilder allowCredentials(
        List<PublicKeyCredentialDescriptor> allowCredentials) {
      this.allowCredentials = allowCredentials;
      return this;
    }
  }
}
