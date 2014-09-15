/*
 * Copyright 2014 Google Inc. All rights reserved.
 * Copyright 2014 Yubico.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://developers.google.com/open-source/licenses/bsd
 */

package com.yubico.u2f.tools.httpserver.servlets;

import com.yubico.u2f.U2fException;
import com.yubico.u2f.server.U2fServer;
import com.yubico.u2f.server.data.Device;
import com.yubico.u2f.server.messages.RegistrationResponse;
import org.simpleframework.http.Request;
import org.simpleframework.http.Response;

import java.io.IOException;
import java.io.PrintStream;

import static com.google.common.base.Preconditions.checkNotNull;

public class EnrollFinishServlet extends HtmlServlet {

  private final U2fServer u2fServer;

  public EnrollFinishServlet(U2fServer u2fServer) {
    this.u2fServer = u2fServer;
  }

  @Override
  public void generateBody(Request req, Response resp, PrintStream body) {

    String enrollData = checkNotNull(req.getParameter("registrationData"));
    String browserData = checkNotNull(req.getParameter("clientData"));
    String sessionId = checkNotNull(req.getParameter("sessionId"));
    RegistrationResponse registrationResponse = new RegistrationResponse(enrollData, browserData);

    try {
      Device tokenData =
              u2fServer.processRegistrationResponse(registrationResponse, System.currentTimeMillis());
      body.println("Success!!!\n\nnew token:\n" + tokenData.toString());
    } catch (U2fException e) {
      body.println("Failure: " + e.toString());
    } catch (IOException e) {
      e.printStackTrace();
    }
  }
}
