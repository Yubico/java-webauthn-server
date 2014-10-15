package com.yubico.u2f.data.messages;

import com.yubico.u2f.U2fException;
import com.yubico.u2f.ClientDataUtils;
import org.apache.commons.codec.binary.Base64;

import static com.google.common.base.Preconditions.checkNotNull;

public class ClientData {

  private final String clientData;

  public ClientData(String clientData) {
    this.clientData = checkNotNull(clientData);
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
