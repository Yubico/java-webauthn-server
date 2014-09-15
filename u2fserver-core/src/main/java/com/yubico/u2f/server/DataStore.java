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

import com.yubico.u2f.server.data.EnrollSessionData;
import com.yubico.u2f.server.data.Device;
import com.yubico.u2f.server.data.SignSessionData;

public interface DataStore {
  
  // attestation certs and trust
  void addTrustedCertificate(X509Certificate certificate) throws IOException;

  Set<X509Certificate> getTrustedCertificates() throws IOException;


  // session handling
  String storeSessionData(EnrollSessionData sessionData) throws IOException;

  SignSessionData getSignSessionData(String sessionId) throws IOException;
  
  EnrollSessionData getEnrollSessionData(String sessionId) throws IOException;

  
  // device management
  void addDevice(String accountName, Device device) throws IOException;

  List<Device> getDevice(String accountName) throws IOException;
  
  void removeDevice(String accountName, byte[] publicKey) throws IOException;
  
  void updateDeviceCounter(String accountName, byte[] publicKey, int newCounterValue) throws IOException;
}
