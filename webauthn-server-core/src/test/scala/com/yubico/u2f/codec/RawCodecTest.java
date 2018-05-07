/*
 * Copyright 2014 Yubico.
 * Copyright 2014 Google Inc. All rights reserved.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://developers.google.com/open-source/licenses/bsd
 */

package com.yubico.u2f.codec;

import com.yubico.u2f.crypto.BouncyCastleCrypto;
import com.yubico.u2f.crypto.Crypto;
import com.yubico.u2f.data.messages.key.RawRegisterResponse;
import org.junit.Test;

import static com.yubico.u2f.data.messages.key.CodecTestUtils.encodeRegisterResponse;
import static com.yubico.u2f.testdata.GnubbyKey.ATTESTATION_CERTIFICATE;
import static com.yubico.u2f.testdata.TestVectors.APP_ID_ENROLL_SHA256;
import static com.yubico.u2f.testdata.TestVectors.CLIENT_DATA_ENROLL_SHA256;
import static com.yubico.u2f.testdata.TestVectors.EXPECTED_REGISTER_SIGNED_BYTES;
import static com.yubico.u2f.testdata.TestVectors.KEY_HANDLE;
import static com.yubico.u2f.testdata.TestVectors.REGISTRATION_DATA_BASE64;
import static com.yubico.u2f.testdata.TestVectors.REGISTRATION_RESPONSE_DATA;
import static com.yubico.u2f.testdata.TestVectors.SIGNATURE_REGISTER;
import static com.yubico.u2f.testdata.TestVectors.USER_PUBLIC_KEY_REGISTER_HEX;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

public class RawCodecTest {

    Crypto crypto = new BouncyCastleCrypto();

    @Test
    public void testEncodeRegisterResponse() throws Exception {
        RawRegisterResponse rawRegisterResponse = new RawRegisterResponse(USER_PUBLIC_KEY_REGISTER_HEX,
                KEY_HANDLE, ATTESTATION_CERTIFICATE, SIGNATURE_REGISTER);
        byte[] encodedBytes = encodeRegisterResponse(rawRegisterResponse);
        assertArrayEquals(REGISTRATION_RESPONSE_DATA, encodedBytes);
    }

    @Test
    public void testEncodeRegisterSignedBytes() {
        byte[] encodedBytes = RawRegisterResponse.packBytesToSign(APP_ID_ENROLL_SHA256,
                CLIENT_DATA_ENROLL_SHA256, KEY_HANDLE, USER_PUBLIC_KEY_REGISTER_HEX);
        assertArrayEquals(EXPECTED_REGISTER_SIGNED_BYTES, encodedBytes);
    }

    @Test
    public void testDecodeRegisterResponse() throws Exception {
        RawRegisterResponse rawRegisterResponse =
                RawRegisterResponse.fromBase64(REGISTRATION_DATA_BASE64, crypto);

        assertEquals(new RawRegisterResponse(USER_PUBLIC_KEY_REGISTER_HEX,
                KEY_HANDLE, ATTESTATION_CERTIFICATE, SIGNATURE_REGISTER), rawRegisterResponse);
    }

}
