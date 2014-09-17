/*
 * Copyright 2014 Yubico.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

package com.yubico.u2f.dropwizard;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.yubico.u2f.U2fException;
import com.yubico.u2f.server.DataStore;
import com.yubico.u2f.server.U2fServer;
import com.yubico.u2f.server.impl.U2fServerImpl;
import com.yubico.u2f.server.messages.RegistrationRequest;
import com.yubico.u2f.server.messages.RegistrationResponse;
import com.yubico.u2f.server.messages.SignRequest;
import com.yubico.u2f.server.messages.SignResponse;
import io.dropwizard.jackson.Jackson;

import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import java.io.IOException;
import java.util.List;
import java.util.Set;

@Path("/u2f")
@Produces(MediaType.APPLICATION_JSON)
public class U2fResource {

  private final U2fServer u2fServer;
  private final ObjectMapper mapper = Jackson.newObjectMapper();

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
  public String bind(@QueryParam("data") String data) throws U2fException, IOException {
    JsonNode jsonData = mapper.readTree(data);
    return u2fServer.processRegistrationResponse(
            new RegistrationResponse(jsonData.get("registrationData").asText(), jsonData.get("clientData").asText()),
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
                       @QueryParam("konstigt -- bort?") String challenge, //ersätt med key_handle
                       @QueryParam("appId") String appId) throws U2fException, IOException {
    u2fServer.processSignResponse(new SignResponse(clientData, signData, challenge, appId));
    return "Success";
  }
}