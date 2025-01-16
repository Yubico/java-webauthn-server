// Copyright (c) 2024, Yubico AB
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

package com.yubico.webauthn.attestation;

import com.yubico.internal.util.BinaryUtil;
import com.yubico.webauthn.RegistrationResult;
import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.data.ByteArray;
import java.nio.ByteBuffer;
import java.security.cert.X509Certificate;
import java.util.Optional;
import lombok.experimental.UtilityClass;

@UtilityClass
public class CertificateUtil {
  public static final String ID_FIDO_GEN_CE_SERNUM = "1.3.6.1.4.1.45724.1.1.2";

  private static byte[] parseSerNum(byte[] bytes) {
    try {
      byte[] extensionValueContents = BinaryUtil.parseDerOctetString(bytes, 0).result;
      byte[] sernumContents = BinaryUtil.parseDerOctetString(extensionValueContents, 0).result;
      return sernumContents;
    } catch (Exception e) {
      throw new IllegalArgumentException(
          "X.509 extension 1.3.6.1.4.1.45724.1.1.2 (id-fido-gen-ce-sernum) is not valid.", e);
    }
  }

  /**
   * Attempt to parse the FIDO enterprise attestation serial number extension from the given
   * certificate.
   *
   * <p>NOTE: This function does NOT verify that the returned serial number is authentic and
   * trustworthy. See:
   *
   * <ul>
   *   <li>{@link RelyingParty.RelyingPartyBuilder#attestationTrustSource(AttestationTrustSource)}
   *   <li>{@link RegistrationResult#isAttestationTrusted()}
   *   <li>{@link RelyingParty.RelyingPartyBuilder#allowUntrustedAttestation(boolean)}
   * </ul>
   *
   * <p>Note that the serial number is an opaque byte array with no defined structure in general.
   * For example, the byte array may or may not represent a big-endian integer depending on the
   * authenticator vendor.
   *
   * <p>The extension has OID <code>1.3.6.1.4.1.45724.1.1.2 (id-fido-gen-ce-sernum)</code>.
   *
   * @param cert the attestation certificate to parse the serial number from.
   * @return The serial number, if present and validly encoded. Empty if the extension is not
   *     present in the certificate.
   * @throws IllegalArgumentException if the extension is present but not validly encoded.
   * @see RelyingParty.RelyingPartyBuilder#attestationTrustSource(AttestationTrustSource)
   * @see RegistrationResult#isAttestationTrusted()
   * @see RelyingParty.RelyingPartyBuilder#allowUntrustedAttestation(boolean)
   * @see <a
   *     href="https://w3c.github.io/webauthn/#sctn-enterprise-packed-attestation-cert-requirements">WebAuthn
   *     Level 3 §8.2.2. Certificate Requirements for Enterprise Packed Attestation Statements</a>
   * @see ByteBuffer#getLong()
   */
  public static Optional<ByteArray> parseFidoSernumExtension(X509Certificate cert) {
    return Optional.ofNullable(cert.getExtensionValue(ID_FIDO_GEN_CE_SERNUM))
        .map(CertificateUtil::parseSerNum)
        .map(ByteArray::new);
  }
}
