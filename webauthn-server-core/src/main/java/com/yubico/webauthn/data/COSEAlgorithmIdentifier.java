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
import com.upokecenter.cbor.CBORException;
import com.upokecenter.cbor.CBORObject;
import java.util.Optional;
import java.util.stream.Stream;
import lombok.Getter;
import lombok.NonNull;

/**
 * A number identifying a cryptographic algorithm. The algorithm identifiers SHOULD be values
 * registered in the IANA COSE Algorithms registry, for instance, -7 for "ES256" and -257 for
 * "RS256".
 *
 * @since 0.3.0
 * @see <a
 *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#typedefdef-cosealgorithmidentifier">§5.10.5.
 *     Cryptographic Algorithm Identifier (typedef COSEAlgorithmIdentifier)</a>
 */
public enum COSEAlgorithmIdentifier {

  /**
   * The signature scheme Ed25519 as defined in <a href="https://www.rfc-editor.org/rfc/rfc8032">RFC
   * 8032</a>.
   *
   * <p>Note: This COSE identifier does not in general identify the full Ed25519 parameter suite,
   * but is specialized to that meaning within the WebAuthn API.
   *
   * @since 1.4.0
   * @see <a href="https://www.iana.org/assignments/cose/cose.xhtml#algorithms">COSE Algorithms
   *     registry</a>
   * @see <a href="https://www.rfc-editor.org/rfc/rfc8032">RFC 8032</a>
   * @see <a href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-alg-identifier">WebAuthn
   *     §5.8.5. Cryptographic Algorithm Identifier (typedef <code>COSEAlgorithmIdentifier</code>
   *     )</a>
   */
  EdDSA(-8),

  /**
   * The signature scheme Ed25519 as defined in <a href="https://www.rfc-editor.org/rfc/rfc8032">RFC
   * 8032</a>.
   *
   * <p>This value is NOT RECOMMENDED, see the <a
   * href="https://w3c.github.io/webauthn/#dom-publickeycredentialcreationoptions-pubkeycredparams">documentation
   * of <code>pubKeyCredParams</code></a>. Use {@link #EdDSA} instead or in addition.
   *
   * @see <a href="https://www.iana.org/assignments/cose/cose.xhtml#algorithms">COSE Algorithms
   *     registry</a>
   * @see <a
   *     href="https://www.ietf.org/archive/id/draft-ietf-jose-fully-specified-algorithms-13.html#name-edwards-curve-digital-signa">Fully-Specified
   *     Algorithms for JOSE and COSE</a>
   * @see <a href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-alg-identifier">WebAuthn
   *     §5.8.5. Cryptographic Algorithm Identifier (typedef <code>COSEAlgorithmIdentifier</code>
   *     )</a>
   */
  Ed25519(-19),

  /**
   * The signature scheme Ed448 as defined in <a href="https://www.rfc-editor.org/rfc/rfc8032">RFC
   * 8032</a>.
   *
   * @since 2.8.0
   * @see <a href="https://www.iana.org/assignments/cose/cose.xhtml#algorithms">COSE Algorithms
   *     registry</a>
   * @see <a
   *     href="https://www.ietf.org/archive/id/draft-ietf-jose-fully-specified-algorithms-13.html#name-edwards-curve-digital-signa">Fully-Specified
   *     Algorithms for JOSE and COSE</a>
   * @see <a href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-alg-identifier">WebAuthn
   *     §5.8.5. Cryptographic Algorithm Identifier (typedef <code>COSEAlgorithmIdentifier</code>
   *     )</a>
   */
  Ed448(-53),

  /**
   * ECDSA with SHA-256 on the NIST P-256 curve.
   *
   * <p>Note: This COSE identifier does not in general restrict the curve to P-256, but is
   * specialized to that meaning within the WebAuthn API.
   *
   * @since 0.3.0
   * @see <a href="https://www.iana.org/assignments/cose/cose.xhtml#algorithms">COSE Algorithms
   *     registry</a>
   * @see <a href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-alg-identifier">WebAuthn
   *     §5.8.5. Cryptographic Algorithm Identifier (typedef <code>COSEAlgorithmIdentifier</code>
   *     )</a>
   */
  ES256(-7),

  /**
   * ECDSA with SHA-384 on the NIST P-384 curve.
   *
   * <p>Note: This COSE identifier does not in general restrict the curve to P-384, but is
   * specialized to that meaning within the WebAuthn API.
   *
   * @since 2.1.0
   * @see <a href="https://www.iana.org/assignments/cose/cose.xhtml#algorithms">COSE Algorithms
   *     registry</a>
   * @see <a href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-alg-identifier">WebAuthn
   *     §5.8.5. Cryptographic Algorithm Identifier (typedef <code>COSEAlgorithmIdentifier</code>
   *     )</a>
   */
  ES384(-35),

  /**
   * ECDSA with SHA-512 on the NIST P-521 curve.
   *
   * <p>Note: This COSE identifier does not in general restrict the curve to P-521, but is
   * specialized to that meaning within the WebAuthn API.
   *
   * @since 2.1.0
   * @see <a href="https://www.iana.org/assignments/cose/cose.xhtml#algorithms">COSE Algorithms
   *     registry</a>
   * @see <a href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-alg-identifier">WebAuthn
   *     §5.8.5. Cryptographic Algorithm Identifier (typedef <code>COSEAlgorithmIdentifier</code>
   *     )</a>
   */
  ES512(-36),

  /**
   * RSASSA-PKCS1-v1_5 using SHA-256.
   *
   * @since 0.3.0
   * @see <a href="https://www.iana.org/assignments/cose/cose.xhtml#algorithms">COSE Algorithms
   *     registry</a>
   */
  RS256(-257),

  /**
   * RSASSA-PKCS1-v1_5 using SHA-384.
   *
   * @since 2.4.0
   * @see <a href="https://www.iana.org/assignments/cose/cose.xhtml#algorithms">COSE Algorithms
   *     registry</a>
   */
  RS384(-258),

  /**
   * RSASSA-PKCS1-v1_5 using SHA-512.
   *
   * @since 2.4.0
   * @see <a href="https://www.iana.org/assignments/cose/cose.xhtml#algorithms">COSE Algorithms
   *     registry</a>
   */
  RS512(-259),

  /**
   * RSASSA-PKCS1-v1_5 using SHA-1.
   *
   * @since 1.5.0
   * @see <a href="https://www.iana.org/assignments/cose/cose.xhtml#algorithms">COSE Algorithms
   *     registry</a>
   */
  RS1(-65535);

  @JsonValue @Getter private final long id;

  COSEAlgorithmIdentifier(long id) {
    this.id = id;
  }

  /**
   * Attempt to parse an integer as a {@link COSEAlgorithmIdentifier}.
   *
   * @param id an integer equal to the {@link #getId() id} of a constant in {@link
   *     COSEAlgorithmIdentifier}
   * @return The {@link COSEAlgorithmIdentifier} instance whose {@link #getId() id} equals <code>id
   *     </code>, if any.
   * @since 0.3.0
   * @see <a href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-alg-identifier">§5.8.5.
   *     Cryptographic Algorithm Identifier (typedef COSEAlgorithmIdentifier)</a>
   */
  public static Optional<COSEAlgorithmIdentifier> fromId(long id) {
    return Stream.of(values()).filter(v -> v.id == id).findAny();
  }

  /**
   * Read the {@link COSEAlgorithmIdentifier} from a public key in COSE_Key format.
   *
   * @param publicKeyCose a public key in COSE_Key format.
   * @return The <code>alg</code> of the <code>publicKeyCose</code> parsed as a {@link
   *     COSEAlgorithmIdentifier}, if possible. Returns empty if the {@link COSEAlgorithmIdentifier}
   *     enum has no constant matching the <code>alg</code> value.
   * @throws IllegalArgumentException if <code>publicKeyCose</code> is not a well-formed COSE_Key.
   * @since 2.1.0
   */
  public static Optional<COSEAlgorithmIdentifier> fromPublicKey(@NonNull ByteArray publicKeyCose) {
    final CBORObject ALG = CBORObject.FromObject(3);
    final int alg;
    try {
      CBORObject cose = CBORObject.DecodeFromBytes(publicKeyCose.getBytes());
      if (!cose.ContainsKey(ALG)) {
        throw new IllegalArgumentException(
            "Public key does not contain an \"alg\"(3) value: " + publicKeyCose);
      }
      CBORObject algCbor = cose.get(ALG);
      if (!(algCbor.isNumber() && algCbor.AsNumber().IsInteger())) {
        throw new IllegalArgumentException(
            "Public key has non-integer \"alg\"(3) value: " + publicKeyCose);
      }
      alg = algCbor.AsInt32();
    } catch (CBORException e) {
      throw new IllegalArgumentException("Failed to parse public key", e);
    }
    return fromId(alg);
  }

  @JsonCreator
  private static COSEAlgorithmIdentifier fromJson(long id) {
    return fromId(id)
        .orElseThrow(
            () -> new IllegalArgumentException("Unknown COSE algorithm identifier: " + id));
  }
}
