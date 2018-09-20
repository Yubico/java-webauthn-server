/*
 * Copyright 2014 Yubico.
 * Copyright 2014 Google Inc. All rights reserved.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://developers.google.com/open-source/licenses/bsd
 */

package com.yubico.webauthn.internal.u2f;

import com.yubico.u2f.testdata.TestVectors;
import com.yubico.webauthn.Crypto;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.internal.u2f.CodecTestUtils;
import com.yubico.webauthn.internal.u2f.RawRegisterResponse;
import com.yubico.webauthn.internal.BouncyCastleCrypto;
import org.junit.Assert;
import org.junit.Test;

import static com.yubico.u2f.testdata.GnubbyKey.ATTESTATION_CERTIFICATE;
import static org.junit.Assert.assertEquals;

public class SerialCodecTest {

    private static final Crypto crypto = new BouncyCastleCrypto();

    @Test
    public void testEncodeRegisterResponse() throws Exception {
        RawRegisterResponse rawRegisterResponse = new RawRegisterResponse(TestVectors.USER_PUBLIC_KEY_REGISTER_HEX,
                TestVectors.KEY_HANDLE, ATTESTATION_CERTIFICATE, TestVectors.SIGNATURE_REGISTER);

        ByteArray encodedBytes = CodecTestUtils.encodeRegisterResponse(rawRegisterResponse);

        Assert.assertEquals(TestVectors.REGISTRATION_RESPONSE_DATA, encodedBytes);
    }

    @Test
    public void testEncodeRegisterSignedBytes() {
        ByteArray encodedBytes = RawRegisterResponse.packBytesToSign(TestVectors.APP_ID_ENROLL_SHA256,
                TestVectors.CLIENT_DATA_ENROLL_SHA256, TestVectors.KEY_HANDLE, TestVectors.USER_PUBLIC_KEY_REGISTER_HEX);

        Assert.assertEquals(TestVectors.EXPECTED_REGISTER_SIGNED_BYTES, encodedBytes);
    }

    @Test
    public void testDecodeRegisterResponse() throws Exception {
        RawRegisterResponse rawRegisterResponse =
                RawRegisterResponse.fromBase64(TestVectors.REGISTRATION_RESPONSE_DATA.getBase64Url(), crypto);

        assertEquals(new RawRegisterResponse(TestVectors.USER_PUBLIC_KEY_REGISTER_HEX,
                TestVectors.KEY_HANDLE, ATTESTATION_CERTIFICATE, TestVectors.SIGNATURE_REGISTER), rawRegisterResponse);
    }

}
