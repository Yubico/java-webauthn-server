/*
 * Copyright 2014 Yubico.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

package com.yubico.u2f.server.impl;

import com.yubico.u2f.server.data.EnrollSessionData;
import com.yubico.u2f.server.data.SecurityKeyData;
import org.junit.Before;
import org.junit.Test;

import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.List;
import java.util.Objects;
import java.util.Set;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class DataStoreProxyTest {

  public static final String ACCOUNT_NAME = "foo";
  DataStoreProxy dataStoreProxy;
  private SecurityKeyData keyData;

  @Before
  public void setup() throws Exception {
    dataStoreProxy = new DataStoreProxy(new HashMap<String, byte[]>());
    keyData = new SecurityKeyData(
            0,
            new byte[]{0x0},
            new byte[]{0x1},
            DummyCertificateGenerator.generate(),
            0
    );
  }

  @Test
  public void shouldStoreSessionData() throws Exception {
    EnrollSessionData sessionData = new EnrollSessionData(ACCOUNT_NAME, "bar", new byte[]{0x0, 0x1, 0x5F});
    String sessionId = dataStoreProxy.storeSessionData(sessionData);
    assertTrue(
            isEqualButNotSameInstance(sessionData, dataStoreProxy.getEnrollSessionData(sessionId))
    );
  }

  @Test
  public void shouldStoreCerts() throws Exception {
    X509Certificate certificate = DummyCertificateGenerator.generate();
    dataStoreProxy.addTrustedCertificate(certificate);
    Set<X509Certificate> certificates = dataStoreProxy.getTrustedCertificates();
    assertTrue(
            isEqualButNotSameInstance(certificate, certificates.iterator().next())
    );
  }

  @Test
  public void shouldStoreSecurityKeys() throws Exception {
    dataStoreProxy.addSecurityKeyData(ACCOUNT_NAME, keyData);
    dataStoreProxy.addSecurityKeyData(ACCOUNT_NAME, new SecurityKeyData(
            1,
            new byte[]{0x2},
            new byte[]{0x3},
            DummyCertificateGenerator.generate(),
            1
    ));
    dataStoreProxy.addSecurityKeyData("other account", new SecurityKeyData(
            2,
            new byte[]{0x4},
            new byte[]{0x5},
            DummyCertificateGenerator.generate(),
            2
    ));
    List<SecurityKeyData> storedKeyData = dataStoreProxy.getSecurityKeyData(ACCOUNT_NAME);
    assertTrue(
            isEqualButNotSameInstance(keyData, storedKeyData.get(0)) ||
            isEqualButNotSameInstance(keyData, storedKeyData.get(1))
    );
  }


  @Test
  public void shouldRemoveSecurityKeys() throws Exception {
    dataStoreProxy.addSecurityKeyData(ACCOUNT_NAME, keyData);
    dataStoreProxy.removeSecurityKey(ACCOUNT_NAME, keyData.getPublicKey());
    assertTrue(dataStoreProxy.getSecurityKeyData(ACCOUNT_NAME).isEmpty());
  }

  private boolean isEqualButNotSameInstance(Object o1, Object o2) {
    return Objects.equals(o1, o2) && o1 != o2;
  }
}
