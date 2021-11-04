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

/**
 * Web Authentication supports several attestation types, defining the semantics of attestation
 * statements and their underlying trust models.
 *
 * @see <a href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-attestation-types">§6.4.3.
 *     Attestation Types</a>
 */
public enum AttestationType {
  /**
   * In the case of basic attestation, the authenticator’s attestation key pair is specific to an
   * authenticator model. Thus, authenticators of the same model often share the same attestation
   * key pair. See <a
   * href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-attestation-privacy">§14.4
   * Attestation Privacy</a> for further information.
   *
   * @see <a href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#basic-attestation">Basic
   *     Attestation</a>
   */
  BASIC,

  /**
   * In the case of self attestation, also known as surrogate basic attestation, the authenticator
   * does not have any specific attestation key. Instead it uses the credential private key to
   * create the attestation signature. Authenticators without meaningful protection measures for an
   * attestation private key typically use this attestation type.
   *
   * @see <a href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#self-attestation">Self
   *     Attestation</a>
   */
  SELF_ATTESTATION,

  /**
   * In this case, an authenticator is based on a Trusted Platform Module (TPM) and holds an
   * authenticator-specific "endorsement key" (EK). This key is used to securely communicate with a
   * trusted third party, the Attestation CA (formerly known as a "Privacy CA"). The authenticator
   * can generate multiple attestation identity key pairs (AIK) and requests an Attestation CA to
   * issue an AIK certificate for each. Using this approach, such an authenticator can limit the
   * exposure of the EK (which is a global correlation handle) to Attestation CA(s). AIKs can be
   * requested for each authenticator-generated public key credential individually, and conveyed to
   * Relying Parties as attestation certificates.
   *
   * <p>Note: This concept typically leads to multiple attestation certificates. The attestation
   * certificate requested most recently is called "active".
   *
   * <p>Note: Attestation statements conveying attestations of this type use the same data structure
   * as attestation statements conveying attestations of type #BASIC, so the two attestation types
   * are, in general, distinguishable only with externally provided knowledge regarding the contents
   * of the attestation certificates conveyed in the attestation statement.
   *
   * @see <a href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#attestation-ca">Attestation
   *     CA</a>
   */
  ATTESTATION_CA,

  /**
   * In this case, the authenticator uses an Anonymization CA which dynamically generates
   * per-credential attestation certificates such that the attestation statements presented to
   * Relying Parties do not provide uniquely identifiable information, e.g., that might be used for
   * tracking purposes.
   *
   * <p>Note: Attestation statements conveying attestations of type AttCA or AnonCA use the same
   * data structure as those of type Basic, so the three attestation types are, in general,
   * distinguishable only with externally provided knowledge regarding the contents of the
   * attestation certificates conveyed in the attestation statement.
   *
   * <p>Note: Attestation statements conveying attestations of this type use the same data structure
   * as attestation statements conveying attestations of type #BASIC, so the two attestation types
   * are, in general, distinguishable only with externally provided knowledge regarding the contents
   * of the attestation certificates conveyed in the attestation statement.
   *
   * @see <a
   *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#anonymization-ca">Anonymization
   *     CA</a>
   */
  ANONYMIZATION_CA,

  /**
   * In this case, the Authenticator receives direct anonymous attestation (DAA) credentials from a
   * single DAA-Issuer. These DAA credentials are used along with blinding to sign the attested
   * credential data. The concept of blinding avoids the DAA credentials being misused as global
   * correlation handle. WebAuthn supports DAA using elliptic curve cryptography and bilinear
   * pairings, called ECDAA. See the <a href=
   * "https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-ecdaa-algorithm-v2.0-id-20180227.html">FIDO
   * ECDAA Algorithm</a> for details.
   *
   * @see <a href= "https://www.w3.org/TR/2019/REC-webauthn-1-20190304/#ecdaa">Elliptic Curve based
   *     Direct Anonymous Attestation (ECDAA)</a>
   * @see <a href=
   *     "https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-ecdaa-algorithm-v2.0-id-20180227.html">FIDO
   *     ECDAA Algorithm</a>
   */
  ECDAA,

  /**
   * In this case, no attestation information is available. See also <a
   * href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-none-attestation">§8.7 None
   * Attestation Statement Format</a>.
   *
   * @see <a href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-none-attestation">§8.7
   *     None Attestation Statement Format</a>
   */
  NONE,

  /**
   * In this case, attestation information is present but was not understood by the library.
   *
   * <p>For example, the attestation statement might be using a new attestation statement format not
   * yet supported by the library.
   *
   * @see <a
   *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-attestation-types">§6.4.3.
   *     Attestation Types</a>
   * @see <a
   *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-defined-attestation-formats">§8.
   *     Defined Attestation Statement Formats</a>
   */
  UNKNOWN
}
