/*
 * Copyright 2014 Yubico.
 * Copyright 2014 Google Inc. All rights reserved.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://developers.google.com/open-source/licenses/bsd
 */

package com.yubico.u2f.data.messages;

import com.google.common.base.Objects;
import com.yubico.u2f.U2F;
import com.yubico.u2f.data.messages.json.JsonObject;

import java.io.Serializable;

import static com.google.common.base.Preconditions.checkNotNull;

public class StartedRegistration extends JsonObject implements Serializable {
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

  public StartedRegistration(String challenge, String appId) {
    this.version = U2F.U2F_VERSION;
    this.challenge = checkNotNull(challenge);
    this.appId = checkNotNull(appId);
  }

  @Override
  public int hashCode() {
    return Objects.hashCode(version, challenge, appId);
  }

  @Override
  public boolean equals(Object obj) {
    if (!(obj instanceof StartedRegistration))
      return false;
    StartedRegistration other = (StartedRegistration) obj;
    return Objects.equal(appId, other.appId)
            && Objects.equal(challenge, other.challenge)
            && Objects.equal(version, other.version);
  }

  public static StartedRegistration fromJson(String json) {
    return GSON.fromJson(json, StartedRegistration.class);
  }
}
