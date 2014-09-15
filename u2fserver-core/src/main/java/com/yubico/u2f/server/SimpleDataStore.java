/*
 * Copyright 2014 Yubico.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

package com.yubico.u2f.server;

public interface SimpleDataStore {

  void put(String key, byte[] data);
  byte[] get(String key);
  boolean containsKey(String key);
}
