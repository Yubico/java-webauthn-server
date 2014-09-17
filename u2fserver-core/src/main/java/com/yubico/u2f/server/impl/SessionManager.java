package com.yubico.u2f.server.impl;

import com.yubico.u2f.server.data.EnrollSessionData;
import com.yubico.u2f.server.data.SignSessionData;

import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public class SessionManager {
  private final Map<String, EnrollSessionData> sessions = Collections.synchronizedMap(
          new HashMap<String, EnrollSessionData>()
  );


  public void storeSessionData(EnrollSessionData sessionData) throws IOException {
    String sessionId = new String(sessionData.getChallenge());
    System.out.println("Storing sessionId "+ sessionId);
    sessions.put(sessionId, sessionData);
  }

  public SignSessionData getSignSessionData(String sessionId) throws IOException {
    return (SignSessionData) getEnrollSessionData(sessionId);
  }

  public EnrollSessionData getEnrollSessionData(String sessionId) throws IOException {
    System.out.println("Reading sessionId: " + sessionId);
    return sessions.get(sessionId);
  }
}
