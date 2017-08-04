/*
 * Copyright 2014 Yubico.
 * Copyright 2014 Google Inc. All rights reserved.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://developers.google.com/open-source/licenses/bsd
 */

package com.yubico.u2f.data.messages;

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonPOJOBuilder;
import com.yubico.u2f.U2fPrimitives;
import com.yubico.u2f.data.messages.json.JsonSerializable;
import com.yubico.u2f.data.messages.json.Persistable;
import com.yubico.u2f.exceptions.U2fBadInputException;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.NonNull;
import lombok.Value;

@Value
@Builder
@AllArgsConstructor
@JsonDeserialize(builder = RegisterRequest.RegisterRequestBuilder.class)
public class RegisterRequest extends JsonSerializable implements Persistable {

    private static final long serialVersionUID = 24349091760814188L;

    /**
     * Version of the protocol that the to-be-registered U2F token must speak. For
     * the version of the protocol described herein, must be "U2F_V2"
     */
    @NonNull String version;

    /**
     * The websafe-base64-encoded challenge.
     */
    @NonNull String challenge;

    /**
     * The application id that the RP would like to assert. The U2F token will
     * enforce that the key handle provided above is associated with this
     * application id. The browser enforces that the calling origin belongs to the
     * application identified by the application id.
     */
    @NonNull String appId;

    public RegisterRequest(String challenge, String appId) {
        this(U2fPrimitives.U2F_VERSION, challenge, appId);
    }

    @Override
    public String getRequestId() {
        return getChallenge();
    }

    public static RegisterRequest fromJson(String json) throws U2fBadInputException {
        return fromJson(json, RegisterRequest.class);
    }

    @JsonPOJOBuilder(withPrefix = "")
    static class RegisterRequestBuilder {}
}
