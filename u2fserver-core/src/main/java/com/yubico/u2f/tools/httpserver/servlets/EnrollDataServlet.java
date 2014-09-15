/*
 * Copyright 2014 Google Inc. All rights reserved.
 * Copyright 2014 Yubico.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://developers.google.com/open-source/licenses/bsd
 */

package com.yubico.u2f.tools.httpserver.servlets;

import java.io.PrintStream;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.yubico.u2f.server.U2fServer;
import com.yubico.u2f.server.messages.RegistrationRequest;
import org.simpleframework.http.Request;
import org.simpleframework.http.Response;
import org.simpleframework.http.Status;

public class EnrollDataServlet extends JavascriptServlet {

  private final U2fServer u2fServer;

  public EnrollDataServlet(U2fServer u2fServer) {
    this.u2fServer = u2fServer;
  }

  @Override
  public void generateJavascript(Request req, Response resp, PrintStream body) throws Exception {
    String userName = req.getParameter("userName");
    if (userName == null) {
      resp.setStatus(Status.BAD_REQUEST);
      return;
    }
    RegistrationRequest registrationRequest = u2fServer.getRegistrationRequest(userName, "http://localhost:8080");

    ObjectMapper mapper = new ObjectMapper();
    mapper.writeValueAsString(registrationRequest);

    body.println(mapper.writeValueAsString(registrationRequest));
  }
}
