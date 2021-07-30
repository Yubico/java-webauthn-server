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

package com.yubico.webauthn.data;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import com.yubico.webauthn.data.exception.Base64UrlException;
import com.yubico.webauthn.data.exception.HexException;
import org.junit.Test;

public class ByteArrayTest {

  @Test
  public void testEncodeBase64Url() {
    byte[] input = "Test".getBytes();
    String base64Data = new ByteArray(input).getBase64Url();

    // No padding.
    assertEquals("VGVzdA", base64Data);
  }

  @Test
  public void decodeTest() throws Base64UrlException {
    String base64Data = "VGVzdA";
    String base64DataWithPadding = "VGVzdA==";
    String base64DataEmpty = "";

    // Verify that Base64 data with and without padding ('=') are decoded correctly.
    String out1 = new String(ByteArray.fromBase64Url(base64Data).getBytes());
    String out2 = new String(ByteArray.fromBase64Url(base64DataWithPadding).getBytes());
    String out3 = new String(ByteArray.fromBase64Url(base64DataEmpty).getBytes());

    assertEquals(out1, out2);
    assertEquals(out1, "Test");
    assertEquals(out3, "");
  }

  @Test
  public void isEmptyTest() throws HexException {
    assertTrue(ByteArray.fromHex("").isEmpty());
    assertFalse(ByteArray.fromHex("00").isEmpty());
  }

  @Test
  public void codecMimeTest() {
    String base64 = "ab+/+/==";
    String base64WithoutPadding = "ab+/+/";
    String expectedRecoded = "ab-_-w";
    String expectedRecodedMime = "ab+/+w==";

    assertEquals(expectedRecoded, ByteArray.fromBase64(base64).getBase64Url());
    assertEquals(expectedRecoded, ByteArray.fromBase64(base64WithoutPadding).getBase64Url());
    assertEquals(expectedRecodedMime, ByteArray.fromBase64(base64).getBase64());
    assertEquals(expectedRecodedMime, ByteArray.fromBase64(base64WithoutPadding).getBase64());
  }

  @Test(expected = Base64UrlException.class)
  public void decodeBadAlphabetTest() throws Base64UrlException {
    ByteArray.fromBase64Url("****");
  }

  @Test(expected = Base64UrlException.class)
  public void decodeBadPaddingTest() throws Base64UrlException {
    ByteArray.fromBase64Url("A===");
  }

  @Test(expected = HexException.class)
  public void decodeBadHexTest() throws HexException {
    ByteArray.fromHex("0g");
  }

  @Test(expected = HexException.class)
  public void decodeBadHexLengthTest() throws HexException {
    ByteArray.fromHex("0");
  }

  @Test
  public void sortTest() throws HexException {
    assertTrue(ByteArray.fromHex("").compareTo(ByteArray.fromHex("")) == 0);
    assertTrue(ByteArray.fromHex("").compareTo(ByteArray.fromHex("00")) < 0);
    assertTrue(ByteArray.fromHex("00").compareTo(ByteArray.fromHex("")) > 0);
    assertTrue(ByteArray.fromHex("11").compareTo(ByteArray.fromHex("0000")) < 0);
    assertTrue(ByteArray.fromHex("1111").compareTo(ByteArray.fromHex("0000")) > 0);
    assertTrue(ByteArray.fromHex("0011").compareTo(ByteArray.fromHex("0000")) > 0);
  }
}
