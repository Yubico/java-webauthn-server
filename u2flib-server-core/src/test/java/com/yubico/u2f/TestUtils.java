/*
 * Copyright 2014 Yubico.
 * Copyright 2014 Google Inc. All rights reserved.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://developers.google.com/open-source/licenses/bsd
 */

package com.yubico.u2f;

import com.google.common.io.BaseEncoding;
import com.google.common.io.ByteArrayDataOutput;
import com.yubico.u2f.data.messages.key.util.CertificateParser;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;

import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.Scanner;

public class TestUtils {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static final BaseEncoding HEX = BaseEncoding.base16().lowerCase();
    public static final BaseEncoding BASE64 = BaseEncoding.base64();

    public static X509Certificate fetchCertificate(InputStream resourceAsStream) {
        Scanner in = new Scanner(resourceAsStream);
        String base64String = in.nextLine();
        return parseCertificate(BASE64.decode(base64String));
    }

    public static X509Certificate parseCertificate(byte[] encodedDerCertificate) {
        try {
            return CertificateParser.parseDer(encodedDerCertificate);
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        }
    }

    public static PrivateKey parsePrivateKey(InputStream is) {
        String keyBytesHex = new Scanner(is).nextLine();
        return parsePrivateKey(keyBytesHex);
    }

    public static PrivateKey parsePrivateKey(String keyBytesHex) {
        try {
            KeyFactory fac = KeyFactory.getInstance("ECDSA");
            X9ECParameters curve = SECNamedCurves.getByName("secp256r1");
            ECParameterSpec curveSpec = new ECParameterSpec(
                    curve.getCurve(), curve.getG(), curve.getN(), curve.getH());
            ECPrivateKeySpec keySpec = new ECPrivateKeySpec(
                    new BigInteger(keyBytesHex, 16),
                    curveSpec);
            return fac.generatePrivate(keySpec);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }

    public static PublicKey parsePublicKey(byte[] keyBytes) {
        try {
            X9ECParameters curve = SECNamedCurves.getByName("secp256r1");
            ECParameterSpec curveSpec = new ECParameterSpec(curve.getCurve(), curve.getG(), curve.getN(),
                    curve.getH());
            ECPoint point = curve.getCurve().decodePoint(keyBytes);
            return KeyFactory.getInstance("ECDSA").generatePublic(
                    new ECPublicKeySpec(point, curveSpec));
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] serialize(Object o) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ObjectOutputStream objectOut = new ObjectOutputStream(out);
        objectOut.writeObject(o);
        objectOut.close();
        return out.toByteArray();
    }

    public static <T> T deserialize(byte[] serialized) throws IOException, ClassNotFoundException {
        ByteArrayInputStream is = new ByteArrayInputStream(serialized);
        ObjectInputStream objectIn = new ObjectInputStream(is);
        T object = (T) objectIn.readObject();
        objectIn.close();
        return  object;
    }

    public static <T> T clone(T input) throws IOException, ClassNotFoundException {
        return deserialize(serialize(input));
    }
}
