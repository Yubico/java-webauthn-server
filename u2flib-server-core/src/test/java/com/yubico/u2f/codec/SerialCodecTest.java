/*
 * Copyright 2014 Yubico.
 * Copyright 2014 Google Inc. All rights reserved.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://developers.google.com/open-source/licenses/bsd
 */

package com.yubico.u2f.codec;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import com.yubico.u2f.TestVectors;
import com.yubico.u2f.data.messages.key.CodecTestUtils;
import org.junit.Test;

import com.yubico.u2f.data.messages.key.RawAuthenticateResponse;
import com.yubico.u2f.data.messages.key.RawRegisterResponse;

public class SerialCodecTest extends TestVectors {

  @Test
  public void testEncodeRegisterResponse() throws Exception {
    RawRegisterResponse rawRegisterResponse = new RawRegisterResponse(USER_PUBLIC_KEY_ENROLL_HEX,
        KEY_HANDLE, VENDOR_CERTIFICATE, SIGNATURE_ENROLL);

    byte[] encodedBytes = CodecTestUtils.encodeRegisterResponse(rawRegisterResponse);

    assertArrayEquals(REGISTRATION_RESPONSE_DATA, encodedBytes);
  }

  @Test
  public void testEncodeRegisterSignedBytes() throws Exception {
    byte[] encodedBytes = RawRegisterResponse.packBytesToSign(APP_ID_ENROLL_SHA256,
            BROWSER_DATA_ENROLL_SHA256, KEY_HANDLE, USER_PUBLIC_KEY_ENROLL_HEX);

    assertArrayEquals(EXPECTED_REGISTER_SIGNED_BYTES, encodedBytes);
  }

  @Test
  public void testDecodeRegisterResponse() throws Exception {
    RawRegisterResponse rawRegisterResponse = RawRegisterResponse.fromBase64(REGISTRATION_RESPONSE_DATA_BASE64);

    assertEquals(new RawRegisterResponse(USER_PUBLIC_KEY_ENROLL_HEX,
        KEY_HANDLE, VENDOR_CERTIFICATE, SIGNATURE_ENROLL), rawRegisterResponse);
  }

  @Test
  public void testEncodeAuthenticateResponse() throws Exception {
    RawAuthenticateResponse rawAuthenticateResponse = new RawAuthenticateResponse(
        RawAuthenticateResponse.USER_PRESENT_FLAG, COUNTER_VALUE, SIGNATURE_AUTHENTICATE);

    byte[] encodedBytes = CodecTestUtils.encodeAuthenticateResponse(rawAuthenticateResponse);

    assertArrayEquals(SIGN_RESPONSE_DATA, encodedBytes);
  }

  @Test
  public void testDecodeAuthenticateResponse() throws Exception {
    RawAuthenticateResponse rawAuthenticateResponse = RawAuthenticateResponse.fromBase64(SIGN_RESPONSE_DATA_BASE64);

    assertEquals(new RawAuthenticateResponse(RawAuthenticateResponse.USER_PRESENT_FLAG, COUNTER_VALUE,
        SIGNATURE_AUTHENTICATE), rawAuthenticateResponse);
  }

  @Test
  public void testEncodeAuthenticateSignedBytes() throws Exception {
    byte[] encodedBytes = RawAuthenticateResponse.packBytesToSign(APP_ID_SIGN_SHA256,
            RawAuthenticateResponse.USER_PRESENT_FLAG, COUNTER_VALUE, BROWSER_DATA_SIGN_SHA256);

    assertArrayEquals(EXPECTED_AUTHENTICATE_SIGNED_BYTES, encodedBytes);
  }
}
