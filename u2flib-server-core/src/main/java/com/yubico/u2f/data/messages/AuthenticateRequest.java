/*
 * Copyright 2014 Yubico.
 * Copyright 2014 Google Inc. All rights reserved.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://developers.google.com/open-source/licenses/bsd
 */

package com.yubico.u2f.data.messages;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.common.base.Objects;
import com.yubico.u2f.U2fPrimitives;
import com.yubico.u2f.data.messages.json.JsonSerializable;
import com.yubico.u2f.data.messages.json.Persistable;
import com.yubico.u2f.exceptions.U2fBadInputException;

import static com.google.common.base.Preconditions.checkNotNull;

public class AuthenticateRequest extends JsonSerializable implements Persistable {

    private static final long serialVersionUID = -27808961388655010L;

    /**
     * Version of the protocol that the to-be-registered U2F token must speak. For
     * the version of the protocol described herein, must be "U2F_V2"
     */
    @JsonProperty
    private final String version = U2fPrimitives.U2F_VERSION;

    /**
     * The websafe-base64-encoded challenge.
     */
    @JsonProperty
    private final String challenge;

    /**
     * The application id that the RP would like to assert. The U2F token will
     * enforce that the key handle provided above is associated with this
     * application id. The browser enforces that the calling origin belongs to the
     * application identified by the application id.
     */
    @JsonProperty
    private final String appId;

    /**
     * websafe-base64 encoding of the key handle obtained from the U2F token
     * during registration.
     */
    @JsonProperty
    private final String keyHandle;

    @JsonCreator
    public AuthenticateRequest(@JsonProperty("challenge") String challenge, @JsonProperty("appId") String appId, @JsonProperty("keyHandle") String keyHandle) {
        this.challenge = checkNotNull(challenge);
        this.appId = checkNotNull(appId);
        this.keyHandle = checkNotNull(keyHandle);
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(version, challenge, appId, keyHandle);
    }

    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof AuthenticateRequest))
            return false;
        AuthenticateRequest other = (AuthenticateRequest) obj;
        return Objects.equal(appId, other.appId)
                && Objects.equal(challenge, other.challenge)
                && Objects.equal(keyHandle, other.keyHandle)
                && Objects.equal(version, other.version);
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

    public static AuthenticateRequest fromJson(String json) throws U2fBadInputException {
        return fromJson(json, AuthenticateRequest.class);
    }
}
