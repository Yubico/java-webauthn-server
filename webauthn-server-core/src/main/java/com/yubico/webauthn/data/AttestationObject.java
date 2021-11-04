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
import com.yubico.internal.util.JacksonCodecs;
import java.io.IOException;
import lombok.NonNull;
import lombok.Value;

/**
 * Authenticators MUST provide some form of attestation. The basic requirement is that the
 * authenticator can produce, for each credential public key, an attestation statement verifiable by
 * the WebAuthn Relying Party. Typically, this attestation statement contains a signature by an
 * attestation private key over the attested credential public key and a challenge, as well as a
 * certificate or similar data providing provenance information for the attestation public key,
 * enabling the Relying Party to make a trust decision. However, if an attestation key pair is not
 * available, then the authenticator MUST perform <a
 * href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#self-attestation">self attestation</a>
 * of the credential public key with the corresponding credential private key. All this information
 * is returned by authenticators any time a new public key credential is generated, in the overall
 * form of an attestation object. The relationship of the attestation object with authenticator data
 * (containing attested credential data) and the attestation statement is illustrated in <a
 * href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#fig-attStructs">figure 5</a>.
 *
 * @see <a href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-attestation">§6.4.
 *     Attestation</a>
 */
@Value
@JsonSerialize(using = AttestationObject.JsonSerializer.class)
public class AttestationObject {

  /**
   * The original raw byte array that this object is decoded from.
   *
   * @see <a href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-attestation">§6.4.
   *     Attestation</a>
   */
  @NonNull private final ByteArray bytes;

  /**
   * The authenticator data embedded inside this attestation object. This is one part of the signed
   * data that the signature in the attestation statement (if any) is computed over.
   */
  @NonNull private final transient AuthenticatorData authenticatorData;

  /**
   * The attestation statement format identifier of this attestation object.
   *
   * @see <a
   *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-defined-attestation-formats">§8.
   *     Defined Attestation Statement Formats</a>
   *     <p>Users of this library should not need to access this value directly.
   */
  @NonNull private final transient String format;

  /**
   * An important component of the attestation object is the attestation statement. This is a
   * specific type of signed data object, containing statements about a public key credential itself
   * and the authenticator that created it. It contains an attestation signature created using the
   * key of the attesting authority (except for the case of self attestation, when it is created
   * using the credential private key).
   *
   * <p>Users of this library should not need to access this value directly.
   */
  @NonNull private final transient ObjectNode attestationStatement;

  /**
   * Decode an {@link AttestationObject} object from a raw attestation object byte array.
   *
   * @throws IOException if <code>bytes</code> cannot be parsed as a CBOR map.
   */
  @JsonCreator
  public AttestationObject(@NonNull ByteArray bytes) throws IOException {
    this.bytes = bytes;

    final JsonNode decoded = JacksonCodecs.cbor().readTree(bytes.getBytes());
    final ByteArray authDataBytes;

    if (!decoded.isObject()) {
      throw new IllegalArgumentException(
          String.format("Attestation object must be a CBOR map, was: %s", decoded.getNodeType()));
    }

    final JsonNode authData = decoded.get("authData");
    if (authData == null) {
      throw new IllegalArgumentException(
          "Required property \"authData\" missing from attestation object: "
              + bytes.getBase64Url());
    } else {
      if (authData.isBinary()) {
        authDataBytes = new ByteArray(authData.binaryValue());
      } else {
        throw new IllegalArgumentException(
            String.format(
                "Property \"authData\" of attestation object must be a CBOR byte array, was: %s. Attestation object: %s",
                authData.getNodeType(), bytes.getBase64Url()));
      }
    }

    final JsonNode format = decoded.get("fmt");
    if (format == null) {
      throw new IllegalArgumentException(
          "Required property \"fmt\" missing from attestation object: " + bytes.getBase64Url());
    } else {
      if (format.isTextual()) {
        this.format = decoded.get("fmt").textValue();
      } else {
        throw new IllegalArgumentException(
            String.format(
                "Property \"fmt\" of attestation object must be a CBOR text value, was: %s. Attestation object: %s",
                format.getNodeType(), bytes.getBase64Url()));
      }
    }

    final JsonNode attStmt = decoded.get("attStmt");
    if (attStmt == null) {
      throw new IllegalArgumentException(
          "Required property \"attStmt\" missing from attestation object: " + bytes.getBase64Url());
    } else {
      if (attStmt.isObject()) {
        this.attestationStatement = (ObjectNode) attStmt;
      } else {
        throw new IllegalArgumentException(
            String.format(
                "Property \"attStmt\" of attestation object must be a CBOR map, was: %s. Attestation object: %s",
                attStmt.getNodeType(), bytes.getBase64Url()));
      }
    }

    authenticatorData = new AuthenticatorData(authDataBytes);
  }

  static class JsonSerializer
      extends com.fasterxml.jackson.databind.JsonSerializer<AttestationObject> {
    @Override
    public void serialize(
        AttestationObject value, JsonGenerator gen, SerializerProvider serializers)
        throws IOException {
      gen.writeString(value.getBytes().getBase64Url());
    }
  }
}
