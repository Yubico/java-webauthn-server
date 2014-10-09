/*
 * Copyright 2014 Yubico.
 * Copyright 2014 Google Inc. All rights reserved.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://developers.google.com/open-source/licenses/bsd
 */

package com.yubico.u2f.server.messages;

import com.google.gson.Gson;

import static com.google.common.base.Preconditions.checkNotNull;

public class TokenAuthenticationResponse {

  /** websafe-base64(client data) */
  private final String clientData;

  /** websafe-base64(raw response from U2F device) */
  private final String signatureData;

  /** challenge originally passed */
  private final String challenge;

  public TokenAuthenticationResponse(String clientData, String signatureData, String challenge) {
    this.clientData = checkNotNull(clientData);
    this.signatureData = checkNotNull(signatureData);
    this.challenge = checkNotNull(challenge);
  }

  public String getClientData() {
    return clientData;
  }

  public String getSignatureData() {
    return signatureData;
  }

  public String getChallenge() {
    return challenge;
  }

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + ((clientData == null) ? 0 : clientData.hashCode());
    result = prime * result + ((challenge == null) ? 0 : challenge.hashCode());
    result = prime * result + ((signatureData == null) ? 0 : signatureData.hashCode());
    return result;
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj)
      return true;
    if (obj == null)
      return false;
    if (getClass() != obj.getClass())
      return false;
    TokenAuthenticationResponse other = (TokenAuthenticationResponse) obj;
    if (clientData == null) {
      if (other.clientData != null)
        return false;
    } else if (!clientData.equals(other.clientData))
      return false;
    if (challenge == null) {
      if (other.challenge != null)
        return false;
    } else if (!challenge.equals(other.challenge))
      return false;
    if (signatureData == null) {
      if (other.signatureData != null)
        return false;
    } else if (!signatureData.equals(other.signatureData))
      return false;
    return true;
  }

  public static TokenAuthenticationResponse fromJson(String json) {
    Gson gson = new Gson();
    return gson.fromJson(json, TokenAuthenticationResponse.class);
  }
}
