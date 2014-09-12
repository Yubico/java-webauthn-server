/*
 * Copyright 2014 Google Inc. All rights reserved.
 * Copyright 2014 Yubico.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://developers.google.com/open-source/licenses/bsd
 */

package com.yubico.u2f.dropwizard.exampleapp;

import com.yubico.u2f.dropwizard.U2fResource;
import io.dropwizard.Application;
import io.dropwizard.setup.Bootstrap;
import io.dropwizard.setup.Environment;

public class ExampleApplication extends Application<Conf> {

  @Override
  public void initialize(Bootstrap<Conf> confBootstrap) {

  }

  @Override
  public void run(Conf conf, Environment environment) throws Exception {
    environment.jersey().register(new U2fResource());
  }

  public static void main(String[] args) throws Exception {
    new ExampleApplication().run(args);
  }
}
