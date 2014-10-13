package com.yubico.u2f.server.messages;

import com.yubico.u2f.U2fException;
import com.yubico.u2f.server.ClientDataUtils;
import org.apache.commons.codec.binary.Base64;

public class ClientData {

  private final String clientData;

  public ClientData(String clientData) {
    this.clientData = clientData;
  }

  @Override
  public String toString() {
    return clientData;
  }

  public String getChallenge() throws U2fException {
    return ClientDataUtils.toJsonObject(Base64.decodeBase64(clientData.getBytes()))
            .get(ClientDataUtils.CHALLENGE_PARAM).getAsString();
  }
}
