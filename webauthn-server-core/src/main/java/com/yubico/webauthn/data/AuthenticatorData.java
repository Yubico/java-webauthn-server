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
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.upokecenter.cbor.CBORException;
import com.upokecenter.cbor.CBORObject;
import com.yubico.internal.util.BinaryUtil;
import com.yubico.internal.util.ExceptionUtil;
import com.yubico.internal.util.JacksonCodecs;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.Optional;
import lombok.NonNull;
import lombok.Value;

/**
 * The authenticator data structure is a byte array of 37 bytes or more. This class presents the
 * authenticator data decoded as a high-level object.
 *
 * <p>The authenticator data structure encodes contextual bindings made by the authenticator. These
 * bindings are controlled by the authenticator itself, and derive their trust from the WebAuthn
 * Relying Party's assessment of the security properties of the authenticator. In one extreme case,
 * the authenticator may be embedded in the client, and its bindings may be no more trustworthy than
 * the client data. At the other extreme, the authenticator may be a discrete entity with
 * high-security hardware and software, connected to the client over a secure channel. In both
 * cases, the Relying Party receives the authenticator data in the same format, and uses its
 * knowledge of the authenticator to make trust decisions.
 *
 * @see <a href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-authenticator-data">§6.1.
 *     Authenticator Data</a>
 */
@Value
@JsonSerialize(using = AuthenticatorData.JsonSerializer.class)
public class AuthenticatorData {

  /**
   * The original raw byte array that this object is decoded from. This is a byte array of 37 bytes
   * or more.
   *
   * @see <a
   *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-authenticator-data">§6.1.
   *     Authenticator Data</a>
   */
  @NonNull private final ByteArray bytes;

  /** The flags bit field. */
  @NonNull private final transient AuthenticatorDataFlags flags;

  /**
   * Attested credential data, if present.
   *
   * <p>This member is present if and only if the {@link AuthenticatorDataFlags#AT} flag is set.
   *
   * @see #flags
   */
  private final transient AttestedCredentialData attestedCredentialData;

  private final transient CBORObject extensions;

  private static final int RP_ID_HASH_INDEX = 0;
  private static final int RP_ID_HASH_END = RP_ID_HASH_INDEX + 32;

  private static final int FLAGS_INDEX = RP_ID_HASH_END;
  private static final int FLAGS_END = FLAGS_INDEX + 1;

  private static final int COUNTER_INDEX = FLAGS_END;
  private static final int COUNTER_END = COUNTER_INDEX + 4;

  private static final int FIXED_LENGTH_PART_END_INDEX = COUNTER_END;

  /** Decode an {@link AuthenticatorData} object from a raw authenticator data byte array. */
  @JsonCreator
  public AuthenticatorData(@NonNull ByteArray bytes) {
    ExceptionUtil.assure(
        bytes.size() >= FIXED_LENGTH_PART_END_INDEX,
        "%s byte array must be at least %d bytes, was %d: %s",
        AuthenticatorData.class.getSimpleName(),
        FIXED_LENGTH_PART_END_INDEX,
        bytes.size(),
        bytes.getBase64Url());

    this.bytes = bytes;

    final byte[] rawBytes = bytes.getBytes();

    this.flags = new AuthenticatorDataFlags(rawBytes[FLAGS_INDEX]);

    if (flags.AT) {
      VariableLengthParseResult parseResult =
          parseAttestedCredentialData(
              flags, Arrays.copyOfRange(rawBytes, FIXED_LENGTH_PART_END_INDEX, rawBytes.length));
      attestedCredentialData = parseResult.getAttestedCredentialData();
      extensions = parseResult.getExtensions();
    } else if (flags.ED) {
      attestedCredentialData = null;
      extensions =
          parseExtensions(
              Arrays.copyOfRange(rawBytes, FIXED_LENGTH_PART_END_INDEX, rawBytes.length));
    } else {
      attestedCredentialData = null;
      extensions = null;
    }
  }

  /** The SHA-256 hash of the RP ID the credential is scoped to. */
  @JsonProperty("rpIdHash")
  public ByteArray getRpIdHash() {
    return new ByteArray(Arrays.copyOfRange(bytes.getBytes(), RP_ID_HASH_INDEX, RP_ID_HASH_END));
  }

  /** The 32-bit unsigned signature counter. */
  public long getSignatureCounter() {
    return BinaryUtil.getUint32(Arrays.copyOfRange(bytes.getBytes(), COUNTER_INDEX, COUNTER_END));
  }

  private static VariableLengthParseResult parseAttestedCredentialData(
      AuthenticatorDataFlags flags, byte[] bytes) {
    final int AAGUID_INDEX = 0;
    final int AAGUID_END = AAGUID_INDEX + 16;

    final int CREDENTIAL_ID_LENGTH_INDEX = AAGUID_END;
    final int CREDENTIAL_ID_LENGTH_END = CREDENTIAL_ID_LENGTH_INDEX + 2;

    ExceptionUtil.assure(
        bytes.length >= CREDENTIAL_ID_LENGTH_END,
        "Attested credential data must contain at least %d bytes, was %d: %s",
        CREDENTIAL_ID_LENGTH_END,
        bytes.length,
        new ByteArray(bytes).getHex());

    byte[] credentialIdLengthBytes =
        Arrays.copyOfRange(bytes, CREDENTIAL_ID_LENGTH_INDEX, CREDENTIAL_ID_LENGTH_END);

    final int L;
    try {
      L = BinaryUtil.getUint16(credentialIdLengthBytes);
    } catch (IllegalArgumentException e) {
      throw new IllegalArgumentException(
          "Invalid credential ID length bytes: " + Arrays.asList(credentialIdLengthBytes), e);
    }

    final int CREDENTIAL_ID_INDEX = CREDENTIAL_ID_LENGTH_END;
    final int CREDENTIAL_ID_END = CREDENTIAL_ID_INDEX + L;

    final int CREDENTIAL_PUBLIC_KEY_INDEX = CREDENTIAL_ID_END;
    final int CREDENTIAL_PUBLIC_KEY_AND_EXTENSION_DATA_END = bytes.length;

    ExceptionUtil.assure(
        bytes.length >= CREDENTIAL_ID_END,
        "Expected credential ID of length %d, but attested credential data and extension data is only %d bytes: %s",
        CREDENTIAL_ID_END,
        bytes.length,
        new ByteArray(bytes).getHex());

    ByteArrayInputStream indefiniteLengthBytes =
        new ByteArrayInputStream(
            Arrays.copyOfRange(
                bytes, CREDENTIAL_PUBLIC_KEY_INDEX, CREDENTIAL_PUBLIC_KEY_AND_EXTENSION_DATA_END));

    final CBORObject credentialPublicKey = CBORObject.Read(indefiniteLengthBytes);
    final CBORObject extensions;

    if (indefiniteLengthBytes.available() > 0) {
      if (flags.ED) {
        try {
          extensions = CBORObject.Read(indefiniteLengthBytes);
        } catch (CBORException e) {
          throw new IllegalArgumentException("Failed to parse extension data", e);
        }
      } else {
        throw new IllegalArgumentException(
            String.format(
                "Flags indicate no extension data, but %d bytes remain after attested credential data.",
                indefiniteLengthBytes.available()));
      }
    } else {
      if (flags.ED) {
        throw new IllegalArgumentException(
            "Flags indicate there should be extension data, but no bytes remain after attested credential data.");
      } else {
        extensions = null;
      }
    }

    return new VariableLengthParseResult(
        AttestedCredentialData.builder()
            .aaguid(new ByteArray(Arrays.copyOfRange(bytes, AAGUID_INDEX, AAGUID_END)))
            .credentialId(
                new ByteArray(Arrays.copyOfRange(bytes, CREDENTIAL_ID_INDEX, CREDENTIAL_ID_END)))
            .credentialPublicKey(new ByteArray(credentialPublicKey.EncodeToBytes()))
            .build(),
        extensions);
  }

  private static CBORObject parseExtensions(byte[] bytes) {
    try {
      return CBORObject.DecodeFromBytes(bytes);
    } catch (CBORException e) {
      throw new IllegalArgumentException("Failed to parse extension data", e);
    }
  }

  @Value
  private static class VariableLengthParseResult {
    AttestedCredentialData attestedCredentialData;
    CBORObject extensions;
  }

  /**
   * Attested credential data, if present.
   *
   * <p>This member is present if and only if the {@link AuthenticatorDataFlags#AT} flag is set.
   *
   * @see #flags
   */
  public Optional<AttestedCredentialData> getAttestedCredentialData() {
    return Optional.ofNullable(attestedCredentialData);
  }

  /**
   * Extension-defined authenticator data, if present.
   *
   * <p>This member is present if and only if the {@link AuthenticatorDataFlags#ED} flag is set.
   *
   * <p>Changes to the returned value are not reflected in the {@link AuthenticatorData} object.
   *
   * @see #flags
   */
  public Optional<CBORObject> getExtensions() {
    return Optional.ofNullable(extensions).map(JacksonCodecs::deepCopy);
  }

  static class JsonSerializer
      extends com.fasterxml.jackson.databind.JsonSerializer<AuthenticatorData> {
    @Override
    public void serialize(
        AuthenticatorData value, JsonGenerator gen, SerializerProvider serializers)
        throws IOException {
      gen.writeString(value.getBytes().getBase64Url());
    }
  }
}
