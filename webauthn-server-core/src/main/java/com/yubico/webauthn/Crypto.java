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

import com.google.common.hash.Hashing;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.COSEAlgorithmIdentifier;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.EllipticCurve;

final class Crypto
{
    // Values from https://apps.nsa.gov/iaarchive/library/ia-guidance/ia-solutions-for-classified/algorithm-guidance/mathematical-routines-for-the-nist-prime-elliptic-curves.cfm
    private static final EllipticCurve P256 = new EllipticCurve(
            new ECFieldFp(
                    new BigInteger("115792089210356248762697446949407573530086143415290314195533631308867097853951")),
            new BigInteger("115792089210356248762697446949407573530086143415290314195533631308867097853948"),
            new BigInteger("41058363725152142129326129780047268409114441015993725554835256314039467401291"));

    static boolean isP256(ECParameterSpec params) {
        return P256.equals(params.getCurve());
    }

    public boolean verifySignature(X509Certificate attestationCertificate, ByteArray signedBytes, ByteArray signature, COSEAlgorithmIdentifier alg) {
        return verifySignature(attestationCertificate.getPublicKey(), signedBytes, signature, alg);
    }

    public boolean verifySignature(PublicKey publicKey, ByteArray signedBytes, ByteArray signatureBytes, COSEAlgorithmIdentifier alg) {
        try {
            Signature signature = Signature.getInstance(WebAuthnCodecs.getJavaAlgorithmName(alg));
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

    public ByteArray hash(ByteArray bytes) {
        //noinspection UnstableApiUsage
        return new ByteArray(Hashing.sha256().hashBytes(bytes.getBytes()).asBytes());
    }

    public ByteArray hash(String str) {
        return hash(new ByteArray(str.getBytes(StandardCharsets.UTF_8)));
    }
}