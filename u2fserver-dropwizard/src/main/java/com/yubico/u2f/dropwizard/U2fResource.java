/*
 * Copyright 2014 Yubico.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

package com.yubico.u2f.dropwizard;

import com.yubico.u2f.U2fException;
import com.yubico.u2f.server.DataStore;
import com.yubico.u2f.server.U2fServer;
import com.yubico.u2f.server.impl.U2fServerImpl;
import com.yubico.u2f.server.messages.RegistrationRequest;
import com.yubico.u2f.server.messages.RegistrationResponse;
import com.yubico.u2f.server.messages.SignRequest;
import com.yubico.u2f.server.messages.SignResponse;

import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.MediaType;
import java.io.IOException;
import java.util.List;
import java.util.Set;

@Path("/u2f")
@Produces(MediaType.APPLICATION_JSON)
public class U2fResource {

  private final U2fServer u2fServer;

  public U2fResource(DataStore dataStore, Set<String> allowedOrigins) {
    this.u2fServer = new U2fServerImpl(dataStore, allowedOrigins);
  }

  @POST
  @Path("enroll")
  public RegistrationRequest enroll(@QueryParam("username") String username, @QueryParam("appId") String appId) throws U2fException, IOException {
    return u2fServer.getRegistrationRequest(username, appId);
  }

  @POST
  @Path("bind")
  public String bind(@QueryParam("registrationData") String registrationData,
                     @QueryParam("clientData") String clientData) throws U2fException, IOException {
    return u2fServer.processRegistrationResponse(
            new RegistrationResponse(registrationData, clientData),
            System.currentTimeMillis()
    ).toString();
  }

  @POST
  @Path("sign")
  public List<SignRequest> sign(@QueryParam("username") String username)
          throws U2fException, IOException {
    return u2fServer.getSignRequest(username, "http://localhost:8080");
  }

  @POST
  @Path("verify")
  public String verify(@QueryParam("clientData") String clientData, @QueryParam("signData") String signData,
                       @QueryParam("konstigt -- bort?") String challenge,
                       @QueryParam("appId") String appId) throws U2fException, IOException {
    u2fServer.processSignResponse(new SignResponse(clientData, signData, challenge, appId));
    return "Success";
  }
}