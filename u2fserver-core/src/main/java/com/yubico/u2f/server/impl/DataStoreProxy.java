/*
 * Copyright 2014 Yubico.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

package com.yubico.u2f.server.impl;

import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import com.google.common.collect.Sets;
import com.yubico.u2f.server.DataStore;
import com.yubico.u2f.server.SessionIdGenerator;
import com.yubico.u2f.server.SimpleDataStore;
import com.yubico.u2f.server.data.Device;
import com.yubico.u2f.server.data.EnrollSessionData;
import com.yubico.u2f.server.data.SignSessionData;

import java.io.*;
import java.security.cert.X509Certificate;
import java.util.*;

public class DataStoreProxy implements DataStore {

  public static final String TRUSTED_CERTIFICATES = "TRUSTED_CERTIFICATES";
  public static final String SESSION_DATA_PREFIX = "SDT";
  public static final String SECURITY_KEY_DATA_PREFIX = "SKD";

  private final SimpleDataStore simpleDataStore;
  private final Map<String, EnrollSessionData> sessions = Collections.synchronizedMap(
          new HashMap<String, EnrollSessionData>()
  );

  public DataStoreProxy(SimpleDataStore simpleDataStore) {
    this.simpleDataStore = simpleDataStore;
  }

  public void addTrustedCertificate(X509Certificate certificate) throws IOException {
    Set<X509Certificate> certs = getTrustedCertificates();
    certs.add(certificate);
    simpleDataStore.put(TRUSTED_CERTIFICATES, serialize(certs));
  }

  @SuppressWarnings("unchecked")
  public Set<X509Certificate> getTrustedCertificates() throws IOException {
    if(!simpleDataStore.containsKey(TRUSTED_CERTIFICATES)) {
      return Sets.newHashSet();
    }
    byte[] trustedCertificates = simpleDataStore.get(TRUSTED_CERTIFICATES);
    return (Set<X509Certificate>) deserialize(trustedCertificates);
  }

  public String storeSessionData(EnrollSessionData sessionData) throws IOException {
    String sessionId = new String(sessionData.getChallenge());
    simpleDataStore.put(SESSION_DATA_PREFIX + sessionId, serialize(sessionData));
    return sessionId;
  }

  public SignSessionData getSignSessionData(String sessionId) throws IOException {
    return (SignSessionData) getEnrollSessionData(sessionId);
  }

  public EnrollSessionData getEnrollSessionData(String sessionId) throws IOException {
    return (EnrollSessionData) deserialize(simpleDataStore.get(SESSION_DATA_PREFIX + sessionId));
  }

  public void addDevice(String accountName, Device device) throws IOException {
    List<Device> tokens = getDevice(accountName);
    tokens.add(device);
    updateSecurityKeyData(accountName, tokens);
  }

  private void updateSecurityKeyData(String accountName, List<Device> tokens) throws IOException {
    simpleDataStore.put(SECURITY_KEY_DATA_PREFIX + accountName, serialize(tokens));
  }

  @SuppressWarnings("unchecked")
  public List<Device> getDevice(String accountName) throws IOException {
    if(!simpleDataStore.containsKey(SECURITY_KEY_DATA_PREFIX + accountName)) {
      return Lists.newArrayList();
    }
    byte[] securityKeyBlob = simpleDataStore.get(SECURITY_KEY_DATA_PREFIX + accountName);
    return (List<Device>) deserialize(securityKeyBlob);
  }

  public void removeDevice(String accountName, byte[] publicKey) throws IOException {
    List<Device> tokens = getDevice(accountName);
    for (Device token : tokens) {
      if (Arrays.equals(token.getPublicKey(), publicKey)) {
        tokens.remove(token);
        updateSecurityKeyData(accountName, tokens);
        return;
      }
    }
  }

  public void updateDeviceCounter(String accountName, byte[] publicKey, int newCounterValue) throws IOException {
    List<Device> tokens = getDevice(accountName);
    for (Device token : tokens) {
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
