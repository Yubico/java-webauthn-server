/*
 * Copyright 2014 Yubico.
 * Copyright 2014 Google Inc. All rights reserved.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://developers.google.com/open-source/licenses/bsd
 */

package com.yubico.u2f;

import com.google.common.collect.ImmutableSet;
import com.yubico.u2f.data.DeviceRegistration;
import com.yubico.u2f.exceptions.U2fException;
import com.yubico.u2f.data.messages.*;
import com.yubico.u2f.testdata.DeterministicKey;
import com.yubico.u2f.testdata.Gnubby;
import org.junit.Before;
import org.junit.Test;

import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.Set;

import static com.yubico.u2f.data.messages.ClientData.canonicalizeOrigin;
import static com.yubico.u2f.testdata.Gnubby.ATTESTATION_CERTIFICATE;
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
    trustedCertificates.add(ATTESTATION_CERTIFICATE);
  }

  @Test
  public void sanitizeOrigin() throws U2fException {
    assertEquals("http://example.com", canonicalizeOrigin("http://example.com"));
    assertEquals("http://example.com", canonicalizeOrigin("http://example.com/"));
    assertEquals("http://example.com", canonicalizeOrigin("http://example.com/foo"));
    assertEquals("http://example.com", canonicalizeOrigin("http://example.com/foo?bar=b"));
    assertEquals("http://example.com", canonicalizeOrigin("http://example.com/foo#fragment"));
    assertEquals("https://example.com", canonicalizeOrigin("https://example.com"));
    assertEquals("https://example.com", canonicalizeOrigin("https://example.com/foo"));
  }

  @Test
  public void finishRegistration() throws Exception {
    StartedRegistration startedRegistration = new StartedRegistration(U2F_VERSION, SERVER_CHALLENGE_ENROLL_BASE64, APP_ID_ENROLL);

    U2F.finishRegistration(startedRegistration, new RegisterResponse(REGISTRATION_RESPONSE_DATA_BASE64, BROWSER_DATA_ENROLL_BASE64), TRUSTED_DOMAINS);
  }

  @Test
  public void finishRegistration2() throws Exception {
    StartedRegistration startedRegistration = new StartedRegistration(U2F_VERSION, SERVER_CHALLENGE_ENROLL_BASE64, APP_ID_ENROLL);

    HashSet<X509Certificate> trustedCertificates = new HashSet<X509Certificate>();
    trustedCertificates.add(Gnubby.ATTESTATION_CERTIFICATE);
    trustedCertificates.add(DeterministicKey.ATTESTATION_CERTIFICATE);

    DeviceRegistration deviceRegistration = U2F.finishRegistration(startedRegistration, new RegisterResponse(DeterministicKey.REGISTRATION_DATA_BASE64, DeterministicKey.BROWSER_DATA_BASE64), TRUSTED_DOMAINS);

    assertEquals(new DeviceRegistration(DeterministicKey.KEY_HANDLE, DeterministicKey.USER_PUBLIC_KEY, DeterministicKey.ATTESTATION_CERTIFICATE, 0), deviceRegistration);
  }

  @Test
  public void finishAuthentication() throws Exception {
    StartedAuthentication startedAuthentication = new StartedAuthentication(U2F_VERSION, SERVER_CHALLENGE_SIGN_BASE64, APP_ID_SIGN, KEY_HANDLE_BASE64);

    AuthenticateResponse tokenResponse = new AuthenticateResponse(BROWSER_DATA_SIGN_BASE64,
        SIGN_RESPONSE_DATA_BASE64, SERVER_CHALLENGE_SIGN_BASE64);

    U2F.finishAuthentication(startedAuthentication, tokenResponse, new DeviceRegistration(KEY_HANDLE, USER_PUBLIC_KEY_SIGN_HEX, ATTESTATION_CERTIFICATE, 0), allowedOrigins);
  }


  @Test(expected = U2fException.class)
  public void finishAuthentication_badOrigin() throws Exception {
    Set<String> allowedOrigins = ImmutableSet.of("some-other-domain.com");
    StartedAuthentication authentication = new StartedAuthentication(U2F_VERSION, SERVER_CHALLENGE_SIGN_BASE64,
            APP_ID_SIGN, KEY_HANDLE_BASE64);

    AuthenticateResponse response = new AuthenticateResponse(BROWSER_DATA_SIGN_BASE64,
        SIGN_RESPONSE_DATA_BASE64, SERVER_CHALLENGE_SIGN_BASE64);

    U2F.finishAuthentication(authentication, response, new DeviceRegistration(KEY_HANDLE, USER_PUBLIC_KEY_SIGN_HEX, ATTESTATION_CERTIFICATE, 0), allowedOrigins);
  }
}
