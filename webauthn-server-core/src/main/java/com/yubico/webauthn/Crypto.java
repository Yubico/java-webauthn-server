/*
 * Copyright 2014 Yubico.
 * Copyright 2014 Google Inc. All rights reserved.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://developers.google.com/open-source/licenses/bsd
 */

package com.yubico.webauthn;

import com.yubico.webauthn.data.ByteArray;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

public interface Crypto {

    boolean verifySignature(X509Certificate attestationCertificate, ByteArray signedBytes, ByteArray signature);

    boolean verifySignature(PublicKey publicKey, ByteArray signedBytes, ByteArray signature);

    PublicKey decodePublicKey(ByteArray encodedPublicKey);

    ByteArray hash(ByteArray bytes);

    ByteArray hash(String str);

}
