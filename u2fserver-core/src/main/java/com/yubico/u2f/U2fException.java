/*
 * Copyright 2014 Google Inc. All rights reserved.
 * Copyright 2014 Yubico.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://developers.google.com/open-source/licenses/bsd
 */

package com.yubico.u2f;

@SuppressWarnings("serial")
public class U2fException extends Exception {

  public U2fException(String message) {
    super(message);
  }

  public U2fException(String message, Throwable cause) {
    super(message, cause);
  }
}
