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
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.yubico.internal.util.ExceptionUtil;
import com.yubico.internal.util.JacksonCodecs;
import com.yubico.webauthn.data.exception.Base64UrlException;
import java.io.IOException;
import java.util.Optional;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NonNull;
import lombok.Value;

/**
 * The client data represents the contextual bindings of both the Relying Party and the client.
 *
 * @see <a
 *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#dictdef-collectedclientdata">§5.10.1.
 *     Client Data Used in WebAuthn Signatures (dictionary CollectedClientData) </a>
 */
@Value
@JsonSerialize(using = CollectedClientData.JsonSerializer.class)
public class CollectedClientData {

  /** The client data returned from the client. */
  @NonNull
  @Getter(AccessLevel.NONE)
  private final ByteArray clientDataJson;

  @NonNull
  @Getter(AccessLevel.NONE)
  private final transient ObjectNode clientData;

  /**
   * The base64url encoding of the challenge provided by the Relying Party. See the <a
   * href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-cryptographic-challenges">§13.1
   * Cryptographic Challenges</a> security consideration.
   */
  @NonNull private final transient ByteArray challenge;

  /**
   * The fully qualified origin of the requester, as provided to the authenticator by the client, in
   * the syntax defined by <a href="https://tools.ietf.org/html/rfc6454">RFC 6454</a>.
   */
  @NonNull private final transient String origin;

  /** The type of the requested operation, set by the client. */
  @NonNull private final transient String type;

  @JsonCreator
  public CollectedClientData(@NonNull ByteArray clientDataJSON)
      throws IOException, Base64UrlException {
    JsonNode clientData = JacksonCodecs.json().readTree(clientDataJSON.getBytes());

    ExceptionUtil.assure(
        clientData != null && clientData.isObject(), "Collected client data must be JSON object.");

    this.clientDataJson = clientDataJSON;
    this.clientData = (ObjectNode) clientData;

    try {
      challenge = ByteArray.fromBase64Url(clientData.get("challenge").textValue());
    } catch (NullPointerException e) {
      throw new IllegalArgumentException("Missing field: \"challenge\"");
    } catch (Base64UrlException e) {
      throw new Base64UrlException("Invalid \"challenge\" value", e);
    }

    try {
      origin = clientData.get("origin").textValue();
    } catch (NullPointerException e) {
      throw new IllegalArgumentException("Missing field: \"origin\"");
    }

    try {
      type = clientData.get("type").textValue();
    } catch (NullPointerException e) {
      throw new IllegalArgumentException("Missing field: \"type\"");
    }
  }

  /**
   * Information about the state of the <a href="https://tools.ietf.org/html/rfc8471">Token Binding
   * protocol</a> used when communicating with the Relying Party. Its absence indicates that the
   * client doesn't support token binding.
   */
  public final Optional<TokenBindingInfo> getTokenBinding() {
    return Optional.ofNullable(clientData.get("tokenBinding"))
        .map(
            tb -> {
              if (tb.isObject()) {
                String status = tb.get("status").textValue();
                return new TokenBindingInfo(
                    TokenBindingStatus.fromJsonString(status),
                    Optional.ofNullable(tb.get("id"))
                        .map(JsonNode::textValue)
                        .map(
                            id -> {
                              try {
                                return ByteArray.fromBase64Url(id);
                              } catch (Base64UrlException e) {
                                throw new IllegalArgumentException(
                                    "Property \"id\" is not valid Base64Url data", e);
                              }
                            }));
              } else {
                throw new IllegalArgumentException(
                    "Property \"tokenBinding\" missing from client data.");
              }
            });
  }

  static class JsonSerializer
      extends com.fasterxml.jackson.databind.JsonSerializer<CollectedClientData> {
    @Override
    public void serialize(
        CollectedClientData value, JsonGenerator gen, SerializerProvider serializers)
        throws IOException {
      gen.writeString(value.clientDataJson.getBase64Url());
    }
  }
}
