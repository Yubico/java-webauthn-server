/*
 * Copyright 2014 Yubico.
 * Copyright 2014 Google Inc. All rights reserved.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://developers.google.com/open-source/licenses/bsd
 */

package com.yubico.u2f.server.impl;

import com.google.common.collect.ImmutableSet;
import com.yubico.u2f.TestVectors;
import com.yubico.u2f.U2fException;
import com.yubico.u2f.server.ClientDataUtils;
import com.yubico.u2f.server.U2F;
import com.yubico.u2f.server.data.Device;
import com.yubico.u2f.server.messages.StartedAuthentication;
import com.yubico.u2f.server.messages.StartedRegistration;
import com.yubico.u2f.server.messages.AuthenticationResponse;
import com.yubico.u2f.server.messages.RegistrationResponse;
import org.junit.Before;
import org.junit.Test;

import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.Set;

import static org.junit.Assert.*;
import static org.mockito.MockitoAnnotations.initMocks;

public class U2FTest extends TestVectors {
  public static final String U2F_VERSION = "U2F_V2";
  final HashSet<String> allowedOrigins = new HashSet<String>();

  @Before
  public void setup() throws Exception {
    initMocks(this);

    allowedOrigins.add("http://example.com");
    HashSet<X509Certificate> trustedCertificates = new HashSet<X509Certificate>();
    trustedCertificates.add(VENDOR_CERTIFICATE);
  }

  @Test
  public void testSanitizeOrigin() {
    assertEquals("http://example.com", ClientDataUtils.canonicalizeOrigin("http://example.com"));
    assertEquals("http://example.com", ClientDataUtils.canonicalizeOrigin("http://example.com/"));
    assertEquals("http://example.com", ClientDataUtils.canonicalizeOrigin("http://example.com/foo"));
    assertEquals("http://example.com", ClientDataUtils.canonicalizeOrigin("http://example.com/foo?bar=b"));
    assertEquals("http://example.com", ClientDataUtils.canonicalizeOrigin("http://example.com/foo#fragment"));
    assertEquals("https://example.com", ClientDataUtils.canonicalizeOrigin("https://example.com"));
    assertEquals("https://example.com", ClientDataUtils.canonicalizeOrigin("https://example.com/foo"));
  }

  @Test
  public void testProcessRegistrationResponse() throws Exception {
    StartedRegistration startedRegistration = new StartedRegistration(U2F_VERSION, SERVER_CHALLENGE_ENROLL_BASE64, APP_ID_ENROLL);

    U2F.finishRegistration(startedRegistration, new RegistrationResponse(REGISTRATION_DATA_BASE64, BROWSER_DATA_ENROLL_BASE64), TRUSTED_DOMAINS);
  }

  @Test
  public void testProcessRegistrationResponse2() throws Exception {
    StartedRegistration startedRegistration = new StartedRegistration(U2F_VERSION, SERVER_CHALLENGE_ENROLL_BASE64, APP_ID_ENROLL);

    HashSet<X509Certificate> trustedCertificates = new HashSet<X509Certificate>();
    trustedCertificates.add(VENDOR_CERTIFICATE);
    trustedCertificates.add(TRUSTED_CERTIFICATE_2);

    Device device = U2F.finishRegistration(startedRegistration, new RegistrationResponse(REGISTRATION_DATA_2_BASE64, BROWSER_DATA_2_BASE64), TRUSTED_DOMAINS);

    assertEquals(new Device(KEY_HANDLE_2, USER_PUBLIC_KEY_2, TRUSTED_CERTIFICATE_2, 0), device);
  }

  @Test
  public void testProcessSignResponse() throws Exception {
    StartedAuthentication startedAuthentication = new StartedAuthentication(U2F_VERSION, SERVER_CHALLENGE_SIGN_BASE64, APP_ID_SIGN, KEY_HANDLE_BASE64);

    AuthenticationResponse tokenResponse = new AuthenticationResponse(BROWSER_DATA_SIGN_BASE64,
        SIGN_RESPONSE_DATA_BASE64, SERVER_CHALLENGE_SIGN_BASE64);

    U2F.finishAuthentication(startedAuthentication, tokenResponse, new Device(KEY_HANDLE, USER_PUBLIC_KEY_SIGN_HEX, VENDOR_CERTIFICATE, 0), allowedOrigins);
  }


  @Test
  public void testProcessSignResponse_badOrigin() throws Exception {
    Set<String> allowedOrigins = ImmutableSet.of("some-other-domain.com");
    StartedAuthentication authentication = new StartedAuthentication(U2F_VERSION, SERVER_CHALLENGE_SIGN_BASE64,
            APP_ID_SIGN, KEY_HANDLE_BASE64);

    AuthenticationResponse response = new AuthenticationResponse(BROWSER_DATA_SIGN_BASE64,
        SIGN_RESPONSE_DATA_BASE64, SERVER_CHALLENGE_SIGN_BASE64);

    try {
      U2F.finishAuthentication(authentication, response, new Device(KEY_HANDLE, USER_PUBLIC_KEY_SIGN_HEX, VENDOR_CERTIFICATE, 0), allowedOrigins);
      fail("expected exception, but didn't get it");
    } catch(U2fException e) {
      assertTrue(e.getMessage().contains("is not a recognized home origin"));
    }
  }
}
