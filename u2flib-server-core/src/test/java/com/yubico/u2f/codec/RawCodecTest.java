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
import com.yubico.u2f.data.messages.key.RawSignResponse;
import com.yubico.u2f.data.messages.key.RawRegisterResponse;
import com.yubico.u2f.testdata.TestVectors;
import org.junit.Test;

import static com.yubico.u2f.data.messages.key.CodecTestUtils.encodeSignResponse;
import static com.yubico.u2f.data.messages.key.CodecTestUtils.encodeRegisterResponse;
import static com.yubico.u2f.testdata.GnubbyKey.ATTESTATION_CERTIFICATE;
import static com.yubico.u2f.testdata.TestVectors.*;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

public class RawCodecTest {

    Crypto crypto = new BouncyCastleCrypto();

    @Test
    public void testEncodeRegisterResponse() throws Exception {
        RawRegisterResponse rawRegisterResponse = new RawRegisterResponse(USER_PUBLIC_KEY_REGISTER_HEX,
                KEY_HANDLE, ATTESTATION_CERTIFICATE, SIGNATURE_REGISTER);
        byte[] encodedBytes = encodeRegisterResponse(rawRegisterResponse);
        assertArrayEquals(TestVectors.REGISTRATION_RESPONSE_DATA, encodedBytes);
    }

    @Test
    public void testEncodeRegisterSignedBytes() throws Exception {
        byte[] encodedBytes = RawRegisterResponse.packBytesToSign(APP_ID_ENROLL_SHA256,
                CLIENT_DATA_ENROLL_SHA256, KEY_HANDLE, USER_PUBLIC_KEY_REGISTER_HEX);
        assertArrayEquals(EXPECTED_REGISTER_SIGNED_BYTES, encodedBytes);
    }

    @Test
    public void testDecodeRegisterResponse() throws Exception {
        RawRegisterResponse rawRegisterResponse =
                RawRegisterResponse.fromBase64(TestVectors.REGISTRATION_DATA_BASE64, crypto);

        assertEquals(new RawRegisterResponse(USER_PUBLIC_KEY_REGISTER_HEX,
                KEY_HANDLE, ATTESTATION_CERTIFICATE, SIGNATURE_REGISTER), rawRegisterResponse);
    }

    @Test
    public void testEncodeSignResponse() throws Exception {
        RawSignResponse rawSignResponse = new RawSignResponse(
                RawSignResponse.USER_PRESENT_FLAG, COUNTER_VALUE, SIGNATURE_SIGN);

        byte[] encodedBytes = encodeSignResponse(rawSignResponse);

        assertArrayEquals(SIGN_RESPONSE_DATA, encodedBytes);
    }

    @Test
    public void testDecodeSignResponse() throws Exception {
        RawSignResponse rawSignResponse =
                RawSignResponse.fromBase64(SIGN_RESPONSE_DATA_BASE64, crypto);

        assertEquals(new RawSignResponse(RawSignResponse.USER_PRESENT_FLAG, COUNTER_VALUE,
            SIGNATURE_SIGN), rawSignResponse);
    }

    @Test
    public void testEncodeSignedBytes() throws Exception {
        byte[] encodedBytes = RawSignResponse.packBytesToSign(APP_ID_SIGN_SHA256,
                RawSignResponse.USER_PRESENT_FLAG, COUNTER_VALUE, CLIENT_DATA_SIGN_SHA256);

        assertArrayEquals(EXPECTED_SIGN_SIGNED_BYTES, encodedBytes);
    }
}
