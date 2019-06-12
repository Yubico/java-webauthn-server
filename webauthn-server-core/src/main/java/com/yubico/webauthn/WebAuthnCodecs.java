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

package com.yubico.webauthn;

import COSE.CoseException;
import COSE.OneKey;
import com.upokecenter.cbor.CBORObject;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.COSEAlgorithmIdentifier;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import org.bouncycastle.jce.provider.BouncyCastleProvider;


final class WebAuthnCodecs {

    public static ByteArray ecPublicKeyToRaw(ECPublicKey key) {
        byte[] x = key.getW().getAffineX().toByteArray();
        byte[] y = key.getW().getAffineY().toByteArray();
        byte[] xPadding = new byte[Math.max(0, 32 - x.length)];
        byte[] yPadding = new byte[Math.max(0, 32 - y.length)];

        Arrays.fill(xPadding, (byte) 0);
        Arrays.fill(yPadding, (byte) 0);

        return new ByteArray(org.bouncycastle.util.Arrays.concatenate(
            new byte[]{ 0x04 },
            org.bouncycastle.util.Arrays.concatenate(
                xPadding,
                Arrays.copyOfRange(x, Math.max(0, x.length - 32), x.length)
            ),
            org.bouncycastle.util.Arrays.concatenate(
                yPadding,
                Arrays.copyOfRange(y, Math.max(0, y.length - 32), y.length)
            )
        ));
    }

    public static ByteArray rawEcdaKeyToCose(ByteArray key) {
        final byte[] keyBytes = key.getBytes();

        if (!(keyBytes.length == 64 || (keyBytes.length == 65 && keyBytes[0] == 0x04))) {
            throw new IllegalArgumentException(String.format(
                "Raw key must be 64 bytes long or be 65 bytes long and start with 0x04, was %d bytes starting with %02x",
                keyBytes.length,
                keyBytes[0]
            ));
        }

        final int start = keyBytes.length == 64 ? 0 : 1;

        Map<Long, Object> coseKey = new HashMap<>();

        coseKey.put(1L, 2L); // Key type: EC
        coseKey.put(3L, COSEAlgorithmIdentifier.ES256.getId());
        coseKey.put(-1L, 1L); // Curve: P-256
        coseKey.put(-2L, Arrays.copyOfRange(keyBytes, start, start + 32)); // x
        coseKey.put(-3L, Arrays.copyOfRange(keyBytes, start + 32, start + 64)); // y

        return new ByteArray(CBORObject.FromObject(coseKey).EncodeToBytes());
    }

    public static ByteArray ecPublicKeyToCose(ECPublicKey key) {
        return rawEcdaKeyToCose(ecPublicKeyToRaw(key));
    }

    public static PublicKey importCosePublicKey(ByteArray key) throws CoseException, IOException, InvalidKeySpecException, NoSuchAlgorithmException {
        CBORObject cose = CBORObject.DecodeFromBytes(key.getBytes());
        final int kty = cose.get(CBORObject.FromObject(1)).AsInt32();
        switch (kty) {
            case 2: return importCoseP256PublicKey(cose);
            case 3: return importCoseRsaPublicKey(cose);
            default:
                throw new IllegalArgumentException("Unsupported key type: " + kty);
        }
    }

    private static PublicKey importCoseRsaPublicKey(CBORObject cose) throws NoSuchAlgorithmException, InvalidKeySpecException {
        RSAPublicKeySpec spec = new RSAPublicKeySpec(
            new BigInteger(1, cose.get(CBORObject.FromObject(-1)).GetByteString()),
            new BigInteger(1, cose.get(CBORObject.FromObject(-2)).GetByteString())
        );
        return KeyFactory.getInstance("RSA", new BouncyCastleProvider()).generatePublic(spec);
    }

    private static ECPublicKey importCoseP256PublicKey(CBORObject cose) throws CoseException, IOException {
        return new COSE.ECPublicKey(new OneKey(cose));
    }

    public static String getSignatureAlgorithmName(PublicKey key) {
        if (key.getAlgorithm().equals("EC")) {
            return "ECDSA";
        } else {
            return key.getAlgorithm();
        }
    }

    public static String jwsAlgorithmNameToJavaAlgorithmName(String alg) {
        switch (alg) {
            case "RS256":
                return "SHA256withRSA";
        }
        throw new IllegalArgumentException("Unknown algorithm: " + alg);
    }

}
