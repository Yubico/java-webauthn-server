/*
 * Copyright 2014 Yubico.
 * Copyright 2014 Google Inc. All rights reserved.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://developers.google.com/open-source/licenses/bsd
 */

package com.yubico.u2f.server;

import java.io.IOException;
import java.util.List;

import com.yubico.u2f.U2fException;
import com.yubico.u2f.server.data.Device;
import com.yubico.u2f.server.data.EnrollSessionData;
import com.yubico.u2f.server.data.SignSessionData;
import com.yubico.u2f.server.messages.RegistrationRequest;
import com.yubico.u2f.server.messages.RegistrationResponse;
import com.yubico.u2f.server.messages.AuthenticationRequest;
import com.yubico.u2f.server.messages.SignResponse;

public interface U2fServer {

  // registration //
  RegistrationRequest startRegistration()
          throws U2fException, IOException;

  Device finishRegistration(RegistrationResponse registrationResponse, EnrollSessionData sessionData)
          throws U2fException, IOException;

  // authentication //
  List<AuthenticationRequest> startAuthentication(String appId, Device device)
          throws U2fException, IOException;

  long finishAuthentication(SignResponse signResponse, SignSessionData sessionData, Device device)
          throws U2fException, IOException;
}
