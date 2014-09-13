/*
 * Copyright 2014 Google Inc. All rights reserved.
 * Copyright 2014 Yubico.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://developers.google.com/open-source/licenses/bsd
 */

package com.yubico.u2f.dropwizard;

import com.google.common.collect.ImmutableSet;
import com.yubico.u2f.U2fException;
import com.yubico.u2f.server.U2FServer;
import com.yubico.u2f.server.impl.MemoryDataStore;
import com.yubico.u2f.server.impl.SessionIdGeneratorImpl;
import com.yubico.u2f.server.impl.U2FServerReferenceImpl;
import com.yubico.u2f.server.messages.RegistrationRequest;
import com.yubico.u2f.server.messages.SignRequest;

import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.MediaType;
import java.util.List;

@Path("/u2f")
@Produces(MediaType.APPLICATION_JSON)
public class U2fResource {

  private final U2FServer u2fServer;

  public U2fResource() {
    this.u2fServer = new U2FServerReferenceImpl(
            new MemoryDataStore(new SessionIdGeneratorImpl()), ImmutableSet.of("http://localhost:8080")
    );
  }

  @POST
  @Path("enroll")
  public RegistrationRequest enroll(@QueryParam("username") String username) throws U2fException {
    return u2fServer.getRegistrationRequest(username, "http://localhost:8080");
  }

  @POST
  @Path("bind")
  public List<SignRequest> bind(@QueryParam("username") String username, @QueryParam("username") String data)
          throws U2fException {

    return u2fServer.getSignRequest(username, "http://localhost:8080");
  }
}