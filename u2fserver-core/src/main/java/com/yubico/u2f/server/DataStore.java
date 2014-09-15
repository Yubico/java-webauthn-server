/*
 * Copyright 2014 Yubico.
 * Copyright 2014 Google Inc. All rights reserved.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://developers.google.com/open-source/licenses/bsd
 */

package com.yubico.u2f.server;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Set;

import com.fasterxml.jackson.core.JsonParseException;
import com.yubico.u2f.server.data.EnrollSessionData;
import com.yubico.u2f.server.data.SecurityKeyData;
import com.yubico.u2f.server.data.SignSessionData;

public interface DataStore {
  
  // attestation certs and trust
  void addTrustedCertificate(X509Certificate certificate);

  Set<X509Certificate> getTrustedCertificates();


  // session handling
  /* sessionId */ String storeSessionData(EnrollSessionData sessionData);

  SignSessionData getSignSessionData(String sessionId);
  
  EnrollSessionData getEnrollSessionData(String sessionId);

  
  // security key management
  void addSecurityKeyData(String accountName, SecurityKeyData securityKeyData);

  List<SecurityKeyData> getSecurityKeyData(String accountName);
  
  void removeSecurityKey(String accountName, byte[] publicKey);
  
  void updateSecurityKeyCounter(String accountName, byte[] publicKey, int newCounterValue);
}
