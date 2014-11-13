/*
 * Copyright 2014 Yubico.
 * Copyright 2014 Google Inc. All rights reserved.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://developers.google.com/open-source/licenses/bsd
 */

package com.yubico.u2f.data.messages;

import com.google.common.base.Objects;
import com.google.gson.Gson;
import com.yubico.u2f.data.messages.json.JsonObject;
import com.yubico.u2f.exceptions.U2fException;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

public class AuthenticateResponse extends JsonObject {
  private static final int MAX_SIZE = 20000;

  /* base64(client data) */
  private final String clientData;

  /* base64(raw response from U2F device) */
  private final String signatureData;

  /* keyHandle originally passed */
  private final String keyHandle;

  private AuthenticateResponse() {
    clientData = null; signatureData = null; keyHandle = null; // Gson requires a no-args constructor.
  }

  public AuthenticateResponse(String clientData, String signatureData, String keyHandle) {
    this.clientData = checkNotNull(clientData);
    this.signatureData = checkNotNull(signatureData);
    this.keyHandle = checkNotNull(keyHandle);
  }

  public ClientData getClientData() throws U2fException {
    return new ClientData(clientData);
  }

  public String getSignatureData() {
    return signatureData;
  }

  public String getKeyHandle() {
    return keyHandle;
  }

  @Override
  public int hashCode() {
    return Objects.hashCode(clientData, signatureData, keyHandle);
  }

  @Override
  public boolean equals(Object obj) {
    if (!(obj instanceof AuthenticateResponse))
      return false;
    AuthenticateResponse other = (AuthenticateResponse) obj;
    return Objects.equal(clientData, other.clientData)
            && Objects.equal(keyHandle, other.keyHandle)
            && Objects.equal(signatureData, other.signatureData);
  }

  public static AuthenticateResponse fromJson(String json) {
    checkArgument(json.length() < MAX_SIZE, "Client response bigger than allowed");
    return GSON.fromJson(json, AuthenticateResponse.class);
  }
}
