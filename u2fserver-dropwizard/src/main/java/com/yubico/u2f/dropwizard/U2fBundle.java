/*
 * Copyright 2014 Google Inc. All rights reserved.
 * Copyright 2014 Yubico.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://developers.google.com/open-source/licenses/bsd
 */

package com.yubico.u2f.dropwizard;

import com.yubico.u2f.server.DataStore;
import io.dropwizard.Bundle;
import io.dropwizard.setup.Bootstrap;
import io.dropwizard.setup.Environment;

import java.util.Set;

public class U2fBundle implements Bundle {

  private final DataStore dataStore;
  private final Set<String> allowedOrigins;

  public U2fBundle(DataStore dataStore, Set<String> allowedOrigins) {

    this.dataStore = dataStore;
    this.allowedOrigins = allowedOrigins;
  }

  @Override
  public void initialize(Bootstrap<?> bootstrap) {

  }

  @Override
  public void run(Environment environment) {
    environment.jersey().register(new U2fResource(dataStore, allowedOrigins));
  }
}
