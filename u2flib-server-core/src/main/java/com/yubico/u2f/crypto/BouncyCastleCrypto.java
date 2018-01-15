/*
 * Copyright 2014 Yubico.
 * Copyright 2014 Google Inc. All rights reserved.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://developers.google.com/open-source/licenses/bsd
 */

package com.yubico.u2f.crypto;

import com.yubico.u2f.data.messages.key.util.U2fB64Encoding;
import com.yubico.u2f.exceptions.U2fBadInputException;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;

import java.security.*;
import java.security.cert.X509Certificate;

public class BouncyCastleCrypto implements Crypto {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Override
    public void checkSignature(X509Certificate attestationCertificate, byte[] signedBytes, byte[] signature)
            throws U2fBadInputException {
        checkSignature(attestationCertificate.getPublicKey(), signedBytes, signature);
    }

    @Override
    public void checkSignature(PublicKey publicKey, byte[] signedBytes, byte[] signature)
            throws U2fBadInputException {
        try {
            Signature ecdsaSignature = Signature.getInstance("SHA256withECDSA");
            ecdsaSignature.initVerify(publicKey);
            ecdsaSignature.update(signedBytes);
            if (!ecdsaSignature.verify(signature)) {
                throw new U2fBadInputException(String.format(
                    "Signature is invalid. Public key: %s, signed data: %s , signature: %s",
                    publicKey,
                    U2fB64Encoding.encode(signedBytes),
                    U2fB64Encoding.encode(signature)
                ));
            }
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(
                String.format(
                    "Failed to verify signature. This could be a problem with your JVM environment, or a bug in u2flib-server-core. Public key: %s, signed data: %s , signature: %s",
                    publicKey,
                    U2fB64Encoding.encode(signedBytes),
                    U2fB64Encoding.encode(signature)
                ),
                e
            );
        }
    }

    @Override
    public PublicKey decodePublicKey(byte[] encodedPublicKey) throws U2fBadInputException {
        try {
            X9ECParameters curve = SECNamedCurves.getByName("secp256r1");
            ECPoint point;
            try {
                point = curve.getCurve().decodePoint(encodedPublicKey);
            } catch (RuntimeException e) {
                throw new U2fBadInputException("Could not parse user public key", e);
            }

            return KeyFactory.getInstance("ECDSA").generatePublic(
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
                "Failed to decode public key: " + U2fB64Encoding.encode(encodedPublicKey),
                e
            );
        }
    }

    @Override
    public byte[] hash(byte[] bytes) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(bytes);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public byte[] hash(String str) {
        return hash(str.getBytes());
    }
}
