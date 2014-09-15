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
import java.util.List;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.yubico.u2f.server.U2fServer;
import com.yubico.u2f.server.messages.SignRequest;
import org.simpleframework.http.Request;
import org.simpleframework.http.Response;
import org.simpleframework.http.Status;

public class SignDataServlet extends JavascriptServlet {

  private final U2fServer u2fServer;

  public SignDataServlet(U2fServer u2fServer) {
    this.u2fServer = u2fServer;
  }

  @Override
  public void generateJavascript(Request req, Response resp, PrintStream body) throws Exception {
    String userName = req.getParameter("userName");
    if (userName == null) {
      resp.setStatus(Status.BAD_REQUEST);
      return;
    }

    List<SignRequest> signRequests = u2fServer.getSignRequest(userName, "http://localhost:8080");

    ObjectMapper mapper = new ObjectMapper();

    body.println("var signData = " + mapper.writeValueAsString(signRequests) + ";");
  }
}
