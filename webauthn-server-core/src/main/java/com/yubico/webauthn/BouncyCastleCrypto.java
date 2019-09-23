// Copyright (c) 2014-2018, Yubico AB
// Copyright (c) 2014, Google Inc.
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
// 3. Neither the name of Google Inc. nor the names of its contributors may be
//    used to endorse or promote products derived from this software without
//    specific prior written permission.
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

import com.yubico.webauthn.data.ByteArray;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;

final class BouncyCastleCrypto {

    private static final Provider provider = new BouncyCastleProvider();

    public Provider getProvider() {
        return provider;
    }

    public boolean verifySignature(X509Certificate attestationCertificate, ByteArray signedBytes, ByteArray signature) {
        return verifySignature(attestationCertificate.getPublicKey(), signedBytes, signature);
    }

    public boolean verifySignature(PublicKey publicKey, ByteArray signedBytes, ByteArray signatureBytes) {
        try {
            final String algName;
            switch (publicKey.getAlgorithm()) {
                case "EC":
                    algName = "SHA256withECDSA";
                    break;

                case "Ed25519":
                    algName = "EDDSA";
                    break;

                case "RSA":
                    algName = "SHA256withRSA";
                    break;

                default:
                    throw new IllegalArgumentException("Unsupported public key algorithm: " + publicKey);
            }
            Signature signature = Signature.getInstance(algName, provider);
            signature.initVerify(publicKey);
            signature.update(signedBytes.getBytes());
            return signature.verify(signatureBytes.getBytes());
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            throw new RuntimeException(
                String.format(
                    "Failed to verify signature. This could be a problem with your JVM environment, or a bug in webauthn-server-core. Public key: %s, signed data: %s , signature: %s",
                    publicKey,
                    signedBytes.getBase64Url(),
                    signatureBytes.getBase64Url()
                ),
                e
            );
        }
    }

    public PublicKey decodePublicKey(ByteArray encodedPublicKey) {
        try {
            X9ECParameters curve = SECNamedCurves.getByName("secp256r1");
            ECPoint point;
            try {
                point = curve.getCurve().decodePoint(encodedPublicKey.getBytes());
            } catch (RuntimeException e) {
                throw new IllegalArgumentException(
                    "Could not parse user public key: " + encodedPublicKey.getBase64Url(),
                    e
                );
            }

            return KeyFactory.getInstance("ECDSA", provider).generatePublic(
                    new ECPublicKeySpec(point,
                            new ECParameterSpec(
                                    curve.getCurve(),
                                    curve.getG(),
                                    curve.getN(),
                                    curve.getH()
                            )
                    )
            );
        } catch (GeneralSecurityException e) { //This should not happen
            throw new RuntimeException(
                "Failed to decode public key: " + encodedPublicKey.getBase64Url(),
                e
            );
        }
    }

    public ByteArray hash(ByteArray bytes) {
        try {
            return new ByteArray(MessageDigest.getInstance("SHA-256", provider).digest(bytes.getBytes()));
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public ByteArray hash(String str) {
        return hash(new ByteArray(str.getBytes()));
    }
}
