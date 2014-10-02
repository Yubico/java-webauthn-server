/*
 * Copyright 2014 Yubico.
 * Copyright 2014 Google Inc. All rights reserved.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://developers.google.com/open-source/licenses/bsd
 */

package com.yubico.u2f.server.messages;

import com.google.common.base.Objects;

public class TokenRegistrationResponse {
  /** websafe-base64(raw registration response message) */
  private final String registrationData;

  /** websafe-base64(UTF8(stringified(client data))) */
  private final String clientData;

  public TokenRegistrationResponse(String registrationData, String clientData) {
    this.registrationData = registrationData;
    this.clientData = clientData;
  }

  public String getRegistrationData() {
    return registrationData;
  }

  public String getClientData() {
    return clientData;
  }

  @Override
  public int hashCode() {
    return Objects.hashCode(registrationData, clientData);
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj)
      return true;
    if (obj == null)
      return false;
    if (getClass() != obj.getClass())
      return false;
    TokenRegistrationResponse other = (TokenRegistrationResponse) obj;
    if (clientData == null) {
      if (other.clientData != null)
        return false;
    } else if (!clientData.equals(other.clientData))
      return false;
    if (registrationData == null) {
      if (other.registrationData != null)
        return false;
    } else if (!registrationData.equals(other.registrationData))
      return false;
    return true;
  }
}
