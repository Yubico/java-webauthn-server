/*
 * Copyright 2014 Yubico.
 * Copyright 2014 Google Inc. All rights reserved.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://developers.google.com/open-source/licenses/bsd
 */

package com.yubico.u2f.server.impl;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.MockitoAnnotations.initMocks;

import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.Set;

import com.google.common.collect.ImmutableSet;
import com.yubico.u2f.TestVectors;
import com.yubico.u2f.U2fException;
import com.yubico.u2f.server.data.Device;
import com.yubico.u2f.server.data.SignSessionData;
import com.yubico.u2f.server.messages.StartedAuthentication;
import com.yubico.u2f.server.messages.TokenAuthenticationResponse;
import org.junit.Before;
import org.junit.Test;

import com.yubico.u2f.server.messages.StartedRegistration;
import com.yubico.u2f.server.messages.TokenRegistrationResponse;

public class U2FServerImplTest extends TestVectors {
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
    assertEquals("http://example.com", U2fServerImpl.canonicalizeOrigin("http://example.com"));
    assertEquals("http://example.com", U2fServerImpl.canonicalizeOrigin("http://example.com/"));
    assertEquals("http://example.com", U2fServerImpl.canonicalizeOrigin("http://example.com/foo"));
    assertEquals("http://example.com", U2fServerImpl.canonicalizeOrigin("http://example.com/foo?bar=b"));
    assertEquals("http://example.com", U2fServerImpl.canonicalizeOrigin("http://example.com/foo#fragment"));
    assertEquals("https://example.com", U2fServerImpl.canonicalizeOrigin("https://example.com"));
    assertEquals("https://example.com", U2fServerImpl.canonicalizeOrigin("https://example.com/foo"));
  }

  @Test
  public void testProcessRegistrationResponse() throws Exception {
    StartedRegistration startedRegistration = new StartedRegistration(U2F_VERSION, SERVER_CHALLENGE_ENROLL_BASE64, APP_ID_ENROLL, allowedOrigins);

    startedRegistration.finish(new TokenRegistrationResponse(REGISTRATION_DATA_BASE64, BROWSER_DATA_ENROLL_BASE64));
  }

  @Test
  public void testProcessRegistrationResponse2() throws Exception {
    StartedRegistration startedRegistration = new StartedRegistration(U2F_VERSION, SERVER_CHALLENGE_ENROLL_BASE64, APP_ID_ENROLL, allowedOrigins);

    HashSet<X509Certificate> trustedCertificates = new HashSet<X509Certificate>();
    trustedCertificates.add(VENDOR_CERTIFICATE);
    trustedCertificates.add(TRUSTED_CERTIFICATE_2);

    Device device = startedRegistration.finish(new TokenRegistrationResponse(REGISTRATION_DATA_2_BASE64, BROWSER_DATA_2_BASE64));

    assertEquals(new Device(KEY_HANDLE_2, USER_PUBLIC_KEY_2, TRUSTED_CERTIFICATE_2, 0), device);
  }

  @Test
  public void testProcessSignResponse() throws Exception {
    StartedAuthentication startedAuthentication = new StartedAuthentication(U2F_VERSION, SERVER_CHALLENGE_SIGN_BASE64, APP_ID_SIGN, KEY_HANDLE_BASE64, allowedOrigins);

    TokenAuthenticationResponse tokenResponse = new TokenAuthenticationResponse(BROWSER_DATA_SIGN_BASE64,
        SIGN_RESPONSE_DATA_BASE64, SERVER_CHALLENGE_SIGN_BASE64, APP_ID_SIGN);

    startedAuthentication.finish(tokenResponse, new Device(KEY_HANDLE, USER_PUBLIC_KEY_SIGN_HEX, VENDOR_CERTIFICATE, 0));
  }


  @Test
  public void testProcessSignResponse_badOrigin() throws Exception {
    SignSessionData signSessionData =
        new SignSessionData(ACCOUNT_NAME, APP_ID_SIGN, SERVER_CHALLENGE_SIGN, USER_PUBLIC_KEY_SIGN_HEX);

    Set<String> allowedOrigins = ImmutableSet.of("some-other-domain.com");
    StartedAuthentication authentication = new StartedAuthentication(U2F_VERSION, SERVER_CHALLENGE_SIGN_BASE64,
            APP_ID_SIGN, KEY_HANDLE_BASE64, allowedOrigins);

    TokenAuthenticationResponse response = new TokenAuthenticationResponse(BROWSER_DATA_SIGN_BASE64,
        SIGN_RESPONSE_DATA_BASE64, SERVER_CHALLENGE_SIGN_BASE64, APP_ID_SIGN);

    try {
      authentication.finish(response, new Device(KEY_HANDLE, USER_PUBLIC_KEY_SIGN_HEX, VENDOR_CERTIFICATE, 0));
      fail("expected exception, but didn't get it");
    } catch(U2fException e) {
      assertTrue(e.getMessage().contains("is not a recognized home origin"));
    }
  }

  /*
  // @Test
  // TODO: put test back in once we have signature sample on a correct browserdata json
  // (currently, this test uses an enrollment browserdata during a signature)
  public void testProcessSignResponse2() throws Exception {
	when(sessionManager.getSignSessionData(anyString())).thenReturn(
	    new SignSessionData(ACCOUNT_NAME, APP_ID_2, SERVER_CHALLENGE_SIGN, USER_PUBLIC_KEY_2));
    when(mockDataStore.getDevice(ACCOUNT_NAME)).thenReturn(
        ImmutableList.of(new Device(0l, KEY_HANDLE_2, USER_PUBLIC_KEY_2, VENDOR_CERTIFICATE, 0)));
    u2fServer = new U2fServerImpl(mockChallengeGenerator,
        mockDataStore, crypto, TRUSTED_DOMAINS, sessionManager);
    SignResponse signResponse = new SignResponse(BROWSER_DATA_2_BASE64, SIGN_DATA_2_BASE64,
        CHALLENGE_2_BASE64, APP_ID_2);

    u2fServer.finishAuthentication(signResponse);
  }*/
}
