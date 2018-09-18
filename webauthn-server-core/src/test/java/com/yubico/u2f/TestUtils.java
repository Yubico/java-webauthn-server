/*
 * Copyright 2014 Yubico.
 * Copyright 2014 Google Inc. All rights reserved.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://developers.google.com/open-source/licenses/bsd
 */

package com.yubico.u2f;

import java.io.InputStream;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Scanner;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;

public class TestUtils {

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

}
