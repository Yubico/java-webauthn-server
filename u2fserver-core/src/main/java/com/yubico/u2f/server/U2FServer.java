/*
 * Copyright 2014 Yubico.
 * Copyright 2014 Google Inc. All rights reserved.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://developers.google.com/open-source/licenses/bsd
 */

package com.yubico.u2f.server;

import java.util.List;

import com.yubico.u2f.U2fException;
import com.yubico.u2f.server.data.SecurityKeyData;
import com.yubico.u2f.server.messages.RegistrationRequest;
import com.yubico.u2f.server.messages.RegistrationResponse;
import com.yubico.u2f.server.messages.SignRequest;
import com.yubico.u2f.server.messages.SignResponse;

public interface U2FServer {

  // registration //
  RegistrationRequest getRegistrationRequest(String accountName, String appId) throws U2fException;

  SecurityKeyData processRegistrationResponse(RegistrationResponse registrationResponse, long currentTimeInMillis)
          throws U2fException;

  // authentication //
  List<SignRequest> getSignRequest(String accountName, String appId) throws U2fException;

  SecurityKeyData processSignResponse(SignResponse signResponse) throws U2fException;
  
  // token management //
  List<SecurityKeyData> getAllSecurityKeys(String accountName);

  void removeSecurityKey(String accountName, byte[] publicKey) throws U2fException;
}
