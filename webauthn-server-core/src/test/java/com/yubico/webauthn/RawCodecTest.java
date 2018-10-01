/*
 * Copyright 2014 Yubico.
 * Copyright 2014 Google Inc. All rights reserved.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://developers.google.com/open-source/licenses/bsd
 */

package com.yubico.webauthn;

import com.yubico.u2f.testdata.GnubbyKey;
import com.yubico.webauthn.data.ByteArray;
import org.junit.Assert;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class RawCodecTest {

    Crypto crypto = new BouncyCastleCrypto();

    @Test
    public void testEncodeRegisterResponse() throws Exception {
        U2fRawRegisterResponse rawRegisterResponse = new U2fRawRegisterResponse(TestVectors.USER_PUBLIC_KEY_REGISTER_HEX,
                TestVectors.KEY_HANDLE, GnubbyKey.ATTESTATION_CERTIFICATE, TestVectors.SIGNATURE_REGISTER);
        ByteArray encodedBytes = CodecTestUtils.encodeRegisterResponse(rawRegisterResponse);
        Assert.assertEquals(TestVectors.REGISTRATION_RESPONSE_DATA, encodedBytes);
    }

    @Test
    public void testEncodeRegisterSignedBytes() {
        ByteArray encodedBytes = U2fRawRegisterResponse.packBytesToSign(TestVectors.APP_ID_ENROLL_SHA256,
                TestVectors.CLIENT_DATA_ENROLL_SHA256, TestVectors.KEY_HANDLE, TestVectors.USER_PUBLIC_KEY_REGISTER_HEX);
        Assert.assertEquals(TestVectors.EXPECTED_REGISTER_SIGNED_BYTES, encodedBytes);
    }

    @Test
    public void testDecodeRegisterResponse() throws Exception {
        U2fRawRegisterResponse rawRegisterResponse =
                U2fRawRegisterResponse.fromBase64(TestVectors.REGISTRATION_RESPONSE_DATA.getBase64Url(), crypto);

        assertEquals(new U2fRawRegisterResponse(TestVectors.USER_PUBLIC_KEY_REGISTER_HEX,
                TestVectors.KEY_HANDLE, GnubbyKey.ATTESTATION_CERTIFICATE, TestVectors.SIGNATURE_REGISTER), rawRegisterResponse);
    }

}
