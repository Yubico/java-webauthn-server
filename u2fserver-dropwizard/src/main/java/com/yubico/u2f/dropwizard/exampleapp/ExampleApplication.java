/*
 * Copyright 2014 Yubico.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE.
 */

package com.yubico.u2f.dropwizard.exampleapp;

import com.google.common.collect.ImmutableSet;
import com.yubico.u2f.dropwizard.U2fBundle;
import com.yubico.u2f.server.SimpleDataStore;
import io.dropwizard.Application;
import io.dropwizard.setup.Bootstrap;
import io.dropwizard.setup.Environment;

import java.util.HashMap;
import java.util.Map;

public class ExampleApplication extends Application<Conf> {

  @Override
  public void initialize(Bootstrap<Conf> confBootstrap) {
    confBootstrap.addBundle(new U2fBundle(new InMemoryStorage(), ImmutableSet.of("http://localhost:8080")));
  }

  @Override
  public void run(Conf conf, Environment environment) {}

  public static void main(String[] args) throws Exception {
    new ExampleApplication().run(args);
  }

  class InMemoryStorage implements SimpleDataStore {

    Map<String, byte[]> map = new HashMap<String, byte[]>();

    @Override
    public void put(String key, byte[] data) {
      map.put(key, data);
    }

    @Override
    public byte[] get(String key) {
      return map.get(key);
    }

    @Override
    public boolean containsKey(String key) {
      return map.containsKey(key);
    }
  }
}
