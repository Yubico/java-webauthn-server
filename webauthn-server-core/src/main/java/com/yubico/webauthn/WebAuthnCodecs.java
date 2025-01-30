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

import com.google.common.primitives.Bytes;
import com.upokecenter.cbor.CBORObject;
import com.yubico.internal.util.BinaryUtil;
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
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

final class WebAuthnCodecs {

  private static final ByteArray EC_PUBLIC_KEY_OID =
      new ByteArray(
          new byte[] {
            0x2A, (byte) 0x86, 0x48, (byte) 0xCE, 0x3D, 2, 1
          }); // OID 1.2.840.10045.2.1 ecPublicKey (ANSI X9.62 public key type)
  private static final ByteArray P256_CURVE_OID =
      new ByteArray(
          new byte[] {
            0x2A, (byte) 0x86, 0x48, (byte) 0xCE, 0x3D, 3, 1, 7 // OID 1.2.840.10045.3.1.7
          });
  private static final ByteArray P384_CURVE_OID =
      new ByteArray(new byte[] {0x2B, (byte) 0x81, 0x04, 0, 34}); // OID 1.3.132.0.34
  private static final ByteArray P512_CURVE_OID =
      new ByteArray(new byte[] {0x2B, (byte) 0x81, 0x04, 0, 35}); // OID 1.3.132.0.35

  private static final ByteArray ED25519_ALG_ID =
      new ByteArray(
          new byte[] {
            // SEQUENCE (5 bytes)
            0x30,
            5,
            // OID (3 bytes)
            0x06,
            3,
            // OID 1.3.101.112
            0x2B,
            101,
            112
          });

  static ByteArray ecPublicKeyToRaw(ECPublicKey key) {

    final int fieldSizeBytes =
        Math.toIntExact(
            Math.round(Math.ceil(key.getParams().getCurve().getField().getFieldSize() / 8.0)));
    byte[] x = key.getW().getAffineX().toByteArray();
    byte[] y = key.getW().getAffineY().toByteArray();
    byte[] xPadding = new byte[Math.max(0, fieldSizeBytes - x.length)];
    byte[] yPadding = new byte[Math.max(0, fieldSizeBytes - y.length)];

    Arrays.fill(xPadding, (byte) 0);
    Arrays.fill(yPadding, (byte) 0);

    return new ByteArray(
        Bytes.concat(
            new byte[] {0x04},
            xPadding,
            Arrays.copyOfRange(x, Math.max(0, x.length - fieldSizeBytes), x.length),
            yPadding,
            Arrays.copyOfRange(y, Math.max(0, y.length - fieldSizeBytes), y.length)));
  }

  static ByteArray rawEcKeyToCose(ByteArray key) {
    final byte[] keyBytes = key.getBytes();
    final int len = keyBytes.length;
    final int lenSub1 = keyBytes.length - 1;
    if (!(len == 64
        || len == 96
        || len == 132
        || (keyBytes[0] == 0x04 && (lenSub1 == 64 || lenSub1 == 96 || lenSub1 == 132)))) {
      throw new IllegalArgumentException(
          String.format(
              "Raw key must be 64, 96 or 132 bytes long, or start with 0x04 and be 65, 97 or 133 bytes long; was %d bytes starting with %02x",
              keyBytes.length, keyBytes[0]));
    }
    final int start = (len == 64 || len == 96 || len == 132) ? 0 : 1;
    final int coordinateLength = (len - start) / 2;

    final Map<Long, Object> coseKey = new HashMap<>();
    coseKey.put(1L, 2L); // Key type: EC

    final COSEAlgorithmIdentifier coseAlg;
    final int coseCrv;
    switch (len - start) {
      case 64:
        coseAlg = COSEAlgorithmIdentifier.ES256;
        coseCrv = 1;
        break;
      case 96:
        coseAlg = COSEAlgorithmIdentifier.ES384;
        coseCrv = 2;
        break;
      case 132:
        coseAlg = COSEAlgorithmIdentifier.ES512;
        coseCrv = 3;
        break;
      default:
        throw new RuntimeException(
            "Failed to determine COSE EC algorithm. This should not be possible, please file a bug report.");
    }
    coseKey.put(3L, coseAlg.getId());
    coseKey.put(-1L, coseCrv);

    coseKey.put(-2L, Arrays.copyOfRange(keyBytes, start, start + coordinateLength)); // x
    coseKey.put(
        -3L,
        Arrays.copyOfRange(keyBytes, start + coordinateLength, start + 2 * coordinateLength)); // y

    return new ByteArray(CBORObject.FromObject(coseKey).EncodeToBytes());
  }

  static PublicKey importCosePublicKey(ByteArray key)
      throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {
    CBORObject cose = CBORObject.DecodeFromBytes(key.getBytes());
    final int kty = cose.get(CBORObject.FromObject(1)).AsInt32();
    switch (kty) {
      case 1:
        return importCoseEdDsaPublicKey(cose);
      case 2:
        return importCoseEcdsaPublicKey(cose);
      case 3:
        return importCoseRsaPublicKey(cose);
      default:
        throw new IllegalArgumentException("Unsupported key type: " + kty);
    }
  }

  private static PublicKey importCoseRsaPublicKey(CBORObject cose)
      throws NoSuchAlgorithmException, InvalidKeySpecException {
    RSAPublicKeySpec spec =
        new RSAPublicKeySpec(
            new BigInteger(1, cose.get(CBORObject.FromObject(-1)).GetByteString()),
            new BigInteger(1, cose.get(CBORObject.FromObject(-2)).GetByteString()));
    return KeyFactory.getInstance("RSA").generatePublic(spec);
  }

  private static PublicKey importCoseEcdsaPublicKey(CBORObject cose)
      throws NoSuchAlgorithmException, InvalidKeySpecException {
    final int crv = cose.get(CBORObject.FromObject(-1)).AsInt32Value();
    final byte[] x = cose.get(CBORObject.FromObject(-2)).GetByteString();
    final byte[] y = cose.get(CBORObject.FromObject(-3)).GetByteString();

    final byte[] curveOid;
    switch (crv) {
      case 1:
        curveOid = P256_CURVE_OID.getBytes();
        break;

      case 2:
        curveOid = P384_CURVE_OID.getBytes();
        break;

      case 3:
        curveOid = P512_CURVE_OID.getBytes();
        break;

      default:
        throw new IllegalArgumentException("Unknown COSE EC2 curve: " + crv);
    }

    final byte[] algId =
        BinaryUtil.encodeDerSequence(
            BinaryUtil.encodeDerObjectId(EC_PUBLIC_KEY_OID.getBytes()),
            BinaryUtil.encodeDerObjectId(curveOid));

    final byte[] rawKey =
        BinaryUtil.encodeDerBitStringWithZeroUnused(
            BinaryUtil.concat(
                new byte[] {0x04}, // Raw EC public key with x and y
                x,
                y));

    final byte[] x509Key = BinaryUtil.encodeDerSequence(algId, rawKey);

    KeyFactory kFact = KeyFactory.getInstance("EC");
    return kFact.generatePublic(new X509EncodedKeySpec(x509Key));
  }

  private static PublicKey importCoseEdDsaPublicKey(CBORObject cose)
      throws InvalidKeySpecException, NoSuchAlgorithmException {
    final int curveId = cose.get(CBORObject.FromObject(-1)).AsInt32();
    switch (curveId) {
      case 6:
        return importCoseEd25519PublicKey(cose);
      default:
        throw new IllegalArgumentException("Unsupported EdDSA curve: " + curveId);
    }
  }

  private static PublicKey importCoseEd25519PublicKey(CBORObject cose)
      throws InvalidKeySpecException, NoSuchAlgorithmException {
    final byte[] rawKey = cose.get(CBORObject.FromObject(-2)).GetByteString();
    final byte[] x509Key =
        BinaryUtil.encodeDerSequence(
            ED25519_ALG_ID.getBytes(), BinaryUtil.encodeDerBitStringWithZeroUnused(rawKey));

    KeyFactory kFact = KeyFactory.getInstance("EdDSA");
    return kFact.generatePublic(new X509EncodedKeySpec(x509Key));
  }

  static String getJavaAlgorithmName(COSEAlgorithmIdentifier alg) {
    switch (alg) {
      case EdDSA:
        return "EDDSA";
      case ES256:
        return "SHA256withECDSA";
      case ES384:
        return "SHA384withECDSA";
      case ES512:
        return "SHA512withECDSA";
      case RS256:
        return "SHA256withRSA";
      case RS384:
        return "SHA384withRSA";
      case RS512:
        return "SHA512withRSA";
      case RS1:
        return "SHA1withRSA";
      default:
        throw new IllegalArgumentException("Unknown algorithm: " + alg);
    }
  }

  static String jwsAlgorithmNameToJavaAlgorithmName(String alg) {
    switch (alg) {
      case "RS256":
        return "SHA256withRSA";
    }
    throw new IllegalArgumentException("Unknown algorithm: " + alg);
  }
}
