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
import com.yubico.u2f.data.messages.json.Persistable;

import java.io.Serializable;

import static com.google.common.base.Preconditions.checkNotNull;

public class AuthenticateRequest extends JsonObject implements Persistable {

    private static final long serialVersionUID = -27808961388655010L;

    /**
     * Version of the protocol that the to-be-registered U2F token must speak. For
     * the version of the protocol described herein, must be "U2F_V2"
     */
    private static final String VERSION = U2F.U2F_VERSION;

    /**
     * The websafe-base64-encoded challenge.
     */
    private final String challenge;

    /**
     * The application id that the RP would like to assert. The U2F token will
     * enforce that the key handle provided above is associated with this
     * application id. The browser enforces that the calling origin belongs to the
     * application identified by the application id.
     */
    private final String appId;

    /**
     * websafe-base64 encoding of the key handle obtained from the U2F token
     * during registration.
     */
    private final String keyHandle;

    private AuthenticateRequest() {
        challenge = null;
        appId = null;
        keyHandle = null; // Gson requires a no-args constructor.
    }

    public AuthenticateRequest(String challenge, String appId, String keyHandle) {
        this.challenge = checkNotNull(challenge);
        this.appId = checkNotNull(appId);
        this.keyHandle = checkNotNull(keyHandle);
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(VERSION, challenge, appId, keyHandle);
    }

    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof AuthenticateRequest))
            return false;
        AuthenticateRequest other = (AuthenticateRequest) obj;
        return Objects.equal(appId, other.appId)
                && Objects.equal(challenge, other.challenge)
                && Objects.equal(keyHandle, other.keyHandle)
                && Objects.equal(VERSION, other.VERSION);
    }

    public String getKeyHandle() {
        return keyHandle;
    }

    public String getChallenge() {
        return challenge;
    }

    public String getAppId() {
        return appId;
    }

    public String getRequestId() {
        return challenge;
    }

    public static AuthenticateRequest fromJson(String json) {
        return GSON.fromJson(json, AuthenticateRequest.class);
    }
}
