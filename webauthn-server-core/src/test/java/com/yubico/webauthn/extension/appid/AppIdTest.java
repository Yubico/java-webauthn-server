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

package com.yubico.webauthn.extension.appid;

import static junit.framework.TestCase.assertFalse;
import static junit.framework.TestCase.assertTrue;
import static org.junit.Assert.assertEquals;

import com.yubico.internal.util.JacksonCodecs;
import java.io.IOException;
import org.junit.Test;

public class AppIdTest {

  @Test
  public void validUrls() {
    assertTrue(isValid("https://www.example.com"));
    assertTrue(isValid("https://internal-server"));
    assertTrue(isValid("https://åäö.se:8443"));
    assertTrue(isValid("https://localhost:8443/myAppId.json"));
  }

  @Test
  public void validUris() {
    assertTrue(isValid("android:apk-key-hash:585215fd5153209a7e246f53286035838a0be227"));
    assertTrue(isValid("ios:bundle-id:com.example.Example"));
  }

  @Test
  public void disallowHttp() {
    assertFalse(isValid("http://www.example.com"));
  }

  @Test
  public void disallowSlashAsPath() {
    assertFalse(isValid("https://www.example.com/"));
  }

  @Test
  public void disallowIP() {
    assertFalse(isValid("https://127.0.0.1:8443"));
    assertFalse(isValid("https://127.0.0.1"));
    assertFalse(isValid("https://127.0.0.1/foo"));
    assertFalse(isValid("https://2001:0db8:0000:0000:0000:ff00:0042:8329"));
    assertFalse(isValid("https://2001:0db8:0000:0000:0000:ff00:0042:8329/åäö"));
  }

  @Test
  public void badSyntax() {
    assertFalse(isValid("https://bad[syntax]"));
    assertFalse(isValid("https//bad"));
  }

  @Test
  public void jsonDecode() throws InvalidAppIdException, IOException {
    assertEquals(
        new AppId("https://example.org"),
        JacksonCodecs.json().readValue("\"https://example.org\"", AppId.class));
  }

  @Test
  public void jsonEncode() throws InvalidAppIdException, IOException {
    assertEquals(
        "\"https://example.org\"",
        JacksonCodecs.json().writeValueAsString(new AppId("https://example.org")));
  }

  private static boolean isValid(String appId) {
    try {
      new AppId(appId);
      return true;
    } catch (InvalidAppIdException e) {
      return false;
    }
  }
}
