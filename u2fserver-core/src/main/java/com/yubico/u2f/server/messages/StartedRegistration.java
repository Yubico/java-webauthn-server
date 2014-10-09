/*
 * Copyright 2014 Yubico.
 * Copyright 2014 Google Inc. All rights reserved.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://developers.google.com/open-source/licenses/bsd
 */

package com.yubico.u2f.server.messages;

import com.google.common.base.Objects;
import com.google.gson.Gson;

public class StartedRegistration {
  /**
   * Version of the protocol that the to-be-registered U2F token must speak. For
   * the version of the protocol described herein, must be "U2F_V2"
   */
  private final String version;

  /** The websafe-base64-encoded challenge. */
  private final String challenge;

  public String getChallenge() {
    return challenge;
  }

  /**
   * The application id that the RP would like to assert. The U2F token will
   * enforce that the key handle provided above is associated with this
   * application id. The browser enforces that the calling origin belongs to the
   * application identified by the application id.
   */
  private final String appId;

  public String getAppId() {
    return appId;
  }

  public StartedRegistration(String version, String challenge, String appId) {
    this.version = version;
    this.challenge = challenge;
    this.appId = appId;
  }

  @Override
  public int hashCode() {
    return Objects.hashCode(version, challenge, appId);
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj)
      return true;
    if (obj == null)
      return false;
    if (getClass() != obj.getClass())
      return false;
    StartedRegistration other = (StartedRegistration) obj;
    if (appId == null) {
      if (other.appId != null)
        return false;
    } else if (!appId.equals(other.appId))
      return false;
    if (challenge == null) {
      if (other.challenge != null)
        return false;
    } else if (!challenge.equals(other.challenge))
      return false;
    if (version == null) {
      if (other.version != null)
        return false;
    } else if (!version.equals(other.version))
      return false;
    return true;
  }

  public String json() {
    Gson gson = new Gson();
    return gson.toJson(this);
  }

  public static StartedRegistration fromJson(String json) {
    Gson gson = new Gson();
    return gson.fromJson(json, StartedRegistration.class);
  }
}
