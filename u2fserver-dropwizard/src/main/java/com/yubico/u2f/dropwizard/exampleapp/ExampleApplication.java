/*
 * Copyright 2014 Yubico.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE.
 */

package com.yubico.u2f.dropwizard.exampleapp;

import com.google.common.collect.ImmutableSet;
import com.yubico.u2f.dropwizard.U2fResource;
import com.yubico.u2f.server.impl.MemoryDataStore;
import com.yubico.u2f.server.impl.SessionIdGeneratorImpl;
import io.dropwizard.Application;
import io.dropwizard.setup.Bootstrap;
import io.dropwizard.setup.Environment;

public class ExampleApplication extends Application<Conf> {

  @Override
  public void initialize(Bootstrap<Conf> confBootstrap) {

  }

  @Override
  public void run(Conf conf, Environment environment) throws Exception {
    environment.jersey().register(new U2fResource(
            new MemoryDataStore(new SessionIdGeneratorImpl()),
            ImmutableSet.of("http://localhost:8080"))
    );
  }

  public static void main(String[] args) throws Exception {
    new ExampleApplication().run(args);
  }
}
