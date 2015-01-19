/*
 * Copyright 2014 Yubico.
 * Copyright 2014 Google Inc. All rights reserved.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://developers.google.com/open-source/licenses/bsd
 */

package com.yubico.u2f.crypto;

import com.yubico.u2f.exceptions.U2fBadInputException;

import java.security.PublicKey;
import java.security.cert.X509Certificate;

public interface Crypto {
    void checkSignature(X509Certificate attestationCertificate, byte[] signedBytes,
                        byte[] signature) throws U2fBadInputException;

    void checkSignature(PublicKey publicKey, byte[] signedBytes,
                        byte[] signature) throws U2fBadInputException;

    PublicKey decodePublicKey(byte[] encodedPublicKey) throws U2fBadInputException;

    byte[] hash(byte[] bytes);

    byte[] hash(String str);
}
