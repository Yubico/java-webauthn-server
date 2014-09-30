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
import static org.mockito.Matchers.anyString;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.MockitoAnnotations.initMocks;

import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.List;

import com.yubico.u2f.U2fException;
import com.yubico.u2f.TestVectors;
import com.yubico.u2f.server.data.EnrollSessionData;
import com.yubico.u2f.server.data.Device;
import com.yubico.u2f.server.data.SignSessionData;
import com.yubico.u2f.server.messages.*;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import com.yubico.u2f.server.ChallengeGenerator;
import com.yubico.u2f.server.Crypto;
import com.yubico.u2f.server.DataStore;
import com.yubico.u2f.server.U2fServer;
import com.yubico.u2f.server.messages.RegistrationRequest;
import com.yubico.u2f.server.messages.RegistrationResponse;
import com.yubico.u2f.server.messages.AuthenticationRequest;

public class U2fServerImplTest extends TestVectors {
  @Mock ChallengeGenerator mockChallengeGenerator;
  @Mock DataStore mockDataStore;
  @Mock SessionManager sessionManager;

  private final Crypto crypto = new BouncyCastleCrypto();
  private U2fServer u2fServer;

  @Before
  public void setup() throws Exception {
    initMocks(this);

    HashSet<X509Certificate> trustedCertificates = new HashSet<X509Certificate>();
    trustedCertificates.add(VENDOR_CERTIFICATE);

    when(mockChallengeGenerator.generateChallenge(ACCOUNT_NAME))
        .thenReturn(SERVER_CHALLENGE_ENROLL);
    when(mockDataStore.getTrustedCertificates())
            .thenReturn(trustedCertificates);
    when(mockDataStore.getDevice(ACCOUNT_NAME))
            .thenReturn(ImmutableList.of(new Device(0L, KEY_HANDLE, USER_PUBLIC_KEY_SIGN_HEX, VENDOR_CERTIFICATE, 0)));
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
  public void testGetRegistrationRequest() throws Exception {
    u2fServer = new U2fServerImpl(mockChallengeGenerator,
        mockDataStore, crypto, TRUSTED_DOMAINS, sessionManager);

    RegistrationRequest registrationRequest = u2fServer.startRegistration(ACCOUNT_NAME, APP_ID_ENROLL);

    assertEquals(new RegistrationRequest("U2F_V2", SERVER_CHALLENGE_ENROLL_BASE64, APP_ID_ENROLL), registrationRequest);
  }

  @Test
  public void testProcessRegistrationResponse() throws Exception {
	when(sessionManager.getEnrollSessionData(anyString())).thenReturn(
        new EnrollSessionData(ACCOUNT_NAME, APP_ID_ENROLL, SERVER_CHALLENGE_ENROLL));
    u2fServer = new U2fServerImpl(mockChallengeGenerator,
        mockDataStore, crypto, TRUSTED_DOMAINS, sessionManager);

    RegistrationResponse registrationResponse = new RegistrationResponse(REGISTRATION_DATA_BASE64,
        BROWSER_DATA_ENROLL_BASE64);

    u2fServer.finishRegistration(registrationResponse, 0L);

    verify(mockDataStore).addDevice(eq(ACCOUNT_NAME),
            eq(new Device(0L, KEY_HANDLE, USER_PUBLIC_KEY_ENROLL_HEX, VENDOR_CERTIFICATE, 0)));
  }

  @Test
  public void testProcessRegistrationResponse2() throws Exception {
	when(sessionManager.getEnrollSessionData(anyString())).thenReturn(
	     new EnrollSessionData(ACCOUNT_NAME, APP_ID_ENROLL, SERVER_CHALLENGE_ENROLL));
    HashSet<X509Certificate> trustedCertificates = new HashSet<X509Certificate>();
    trustedCertificates.add(VENDOR_CERTIFICATE);
    trustedCertificates.add(TRUSTED_CERTIFICATE_2);
    when(mockDataStore.getTrustedCertificates()).thenReturn(trustedCertificates);
    u2fServer = new U2fServerImpl(mockChallengeGenerator,
        mockDataStore, crypto, TRUSTED_DOMAINS, sessionManager);

    RegistrationResponse registrationResponse = new RegistrationResponse(REGISTRATION_DATA_2_BASE64,
        BROWSER_DATA_2_BASE64);

    u2fServer.finishRegistration(registrationResponse, 0L);

    verify(mockDataStore).addDevice(eq(ACCOUNT_NAME),
            eq(new Device(0L, KEY_HANDLE_2, USER_PUBLIC_KEY_2, TRUSTED_CERTIFICATE_2, 0)));
  }

  @Test
  public void testGetSignRequest() throws Exception {
    u2fServer = new U2fServerImpl(mockChallengeGenerator,
        mockDataStore, crypto, TRUSTED_DOMAINS, sessionManager);
    when(mockChallengeGenerator.generateChallenge(ACCOUNT_NAME)).thenReturn(SERVER_CHALLENGE_SIGN);

    List<AuthenticationRequest> authenticationRequest = u2fServer.startAuthentication(ACCOUNT_NAME, APP_ID_SIGN);

    assertEquals(new AuthenticationRequest("U2F_V2", SERVER_CHALLENGE_SIGN_BASE64, APP_ID_SIGN,
        KEY_HANDLE_BASE64), authenticationRequest.get(0));
  }

  @Test
  public void testProcessSignResponse() throws Exception {
	when(sessionManager.getSignSessionData(anyString())).thenReturn(
	    new SignSessionData(ACCOUNT_NAME, APP_ID_SIGN, SERVER_CHALLENGE_SIGN, USER_PUBLIC_KEY_SIGN_HEX));
    u2fServer = new U2fServerImpl(mockChallengeGenerator,
        mockDataStore, crypto, TRUSTED_DOMAINS, sessionManager);
    SignResponse signResponse = new SignResponse(BROWSER_DATA_SIGN_BASE64,
        SIGN_RESPONSE_DATA_BASE64, SERVER_CHALLENGE_SIGN_BASE64, APP_ID_SIGN);

    u2fServer.finishAuthentication(signResponse);
  }

  @Test
  public void testProcessSignResponse_badOrigin() throws Exception {
    when(sessionManager.getSignSessionData(anyString())).thenReturn(
        new SignSessionData(ACCOUNT_NAME, APP_ID_SIGN, SERVER_CHALLENGE_SIGN, USER_PUBLIC_KEY_SIGN_HEX));
    u2fServer = new U2fServerImpl(mockChallengeGenerator,
        mockDataStore, crypto, ImmutableSet.of("some-other-domain.com"), sessionManager);
    SignResponse signResponse = new SignResponse(BROWSER_DATA_SIGN_BASE64,
        SIGN_RESPONSE_DATA_BASE64, SERVER_CHALLENGE_SIGN_BASE64, APP_ID_SIGN);

    try {
      u2fServer.finishAuthentication(signResponse);
      fail("expected exception, but didn't get it");
    } catch(U2fException e) {
      assertTrue(e.getMessage().contains("is not a recognized home origin"));
    }
  }
  
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
  }
}
