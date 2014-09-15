/*
 * Copyright 2014 Yubico.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

package com.yubico.u2f.server.impl;

import com.google.common.collect.Lists;
import com.google.common.collect.Sets;
import com.yubico.u2f.server.SessionIdGenerator;
import com.yubico.u2f.server.data.EnrollSessionData;
import com.yubico.u2f.server.data.SecurityKeyData;
import com.yubico.u2f.server.data.SignSessionData;

import java.io.*;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class DataStoreProxy implements DataStore {

  public static final String TRUSTED_CERTIFICATES = "TRUSTED_CERTIFICATES";
  public static final String SESSION_DATA_PREFIX = "SDT";
  public static final String SECURITY_KEY_DATA_PREFIX = "SKD";

  private final Map<String, byte[]> keyValueStorage;
  private final SessionIdGenerator sessionIdGenerator;

  public DataStoreProxy(Map<String, byte[]> keyValueStorage) {
    this.keyValueStorage = keyValueStorage;
    this.sessionIdGenerator = new SessionIdGeneratorImpl();
  }

  public void addTrustedCertificate(X509Certificate certificate) throws IOException {
    Set<X509Certificate> certs = getTrustedCertificates();
    certs.add(certificate);
    keyValueStorage.put(TRUSTED_CERTIFICATES, serialize(certs));
  }

  public Set<X509Certificate> getTrustedCertificates() throws IOException {
    if(!keyValueStorage.containsKey(TRUSTED_CERTIFICATES)) {
      return Sets.newHashSet();
    }
    byte[] trustedCertificates = keyValueStorage.get(TRUSTED_CERTIFICATES);
    return (Set<X509Certificate>) deserialize(trustedCertificates);
  }

  public String storeSessionData(EnrollSessionData sessionData) throws IOException {
    String sessionId = sessionIdGenerator.generateSessionId(sessionData.getAccountName());
    keyValueStorage.put(SESSION_DATA_PREFIX + sessionId, serialize(sessionData));
    return sessionId;
  }

  public SignSessionData getSignSessionData(String sessionId) throws IOException {
    return (SignSessionData) getEnrollSessionData(sessionId);
  }

  public EnrollSessionData getEnrollSessionData(String sessionId) throws IOException {
    return (EnrollSessionData) deserialize(keyValueStorage.get(SESSION_DATA_PREFIX + sessionId));
  }

  public void addSecurityKeyData(String accountName, SecurityKeyData securityKeyData) throws IOException {
    List<SecurityKeyData> tokens = getSecurityKeyData(accountName);
    tokens.add(securityKeyData);
    updateSecurityKeyData(accountName, tokens);
  }

  private void updateSecurityKeyData(String accountName, List<SecurityKeyData> tokens) throws IOException {
    keyValueStorage.put(SECURITY_KEY_DATA_PREFIX + accountName, serialize(tokens));
  }

  public List<SecurityKeyData> getSecurityKeyData(String accountName) throws IOException {
    if(!keyValueStorage.containsKey(SECURITY_KEY_DATA_PREFIX + accountName)) {
      return Lists.newArrayList();
    }
    byte[] securityKeyBlob = keyValueStorage.get(SECURITY_KEY_DATA_PREFIX + accountName);
    return (List<SecurityKeyData>) deserialize(securityKeyBlob);
  }

  public void removeSecurityKey(String accountName, byte[] publicKey) throws IOException {
    List<SecurityKeyData> tokens = getSecurityKeyData(accountName);
    for (SecurityKeyData token : tokens) {
      if (Arrays.equals(token.getPublicKey(), publicKey)) {
        tokens.remove(token);
        updateSecurityKeyData(accountName, tokens);
        return;
      }
    }
  }

  public void updateSecurityKeyCounter(String accountName, byte[] publicKey, int newCounterValue) throws IOException {
    List<SecurityKeyData> tokens = getSecurityKeyData(accountName);
    for (SecurityKeyData token : tokens) {
      if (Arrays.equals(token.getPublicKey(), publicKey)) {
        token.setCounter(newCounterValue);
        updateSecurityKeyData(accountName, tokens);
        return;
      }
    }
  }

  private static Object deserialize(byte[] bytes) throws IOException {
    ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(bytes));
    try {
      return ois.readObject();
    } catch (ClassNotFoundException e) {
      throw new RuntimeException();
    }
  }

  private static byte[] serialize(Object object) throws IOException {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    ObjectOutputStream oos = new ObjectOutputStream(baos);
    oos.writeObject(object);
    return baos.toByteArray();
  }
}
