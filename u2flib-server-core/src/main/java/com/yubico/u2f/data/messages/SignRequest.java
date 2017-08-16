/*
 * Copyright 2014 Yubico.
 * Copyright 2014 Google Inc. All rights reserved.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://developers.google.com/open-source/licenses/bsd
 */

package com.yubico.u2f.data.messages;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonPOJOBuilder;
import com.yubico.u2f.U2fPrimitives;
import com.yubico.u2f.data.messages.json.JsonSerializable;
import com.yubico.u2f.data.messages.json.Persistable;
import com.yubico.u2f.exceptions.U2fBadInputException;
import lombok.Builder;
import lombok.NonNull;
import lombok.Value;

@Value
@Builder
@JsonDeserialize(builder = SignRequest.SignRequestBuilder.class)
public class SignRequest extends JsonSerializable implements Persistable {

    private static final long serialVersionUID = -27808961388655010L;

    /**
     * Version of the protocol that the to-be-registered U2F token must speak. For
     * the version of the protocol described herein, must be "U2F_V2"
     */
    @JsonProperty
    @NonNull @Builder.Default String version = U2fPrimitives.U2F_VERSION;

    /**
     * The websafe-base64-encoded challenge.
     */
    @JsonProperty
    @NonNull String challenge;

    /**
     * The application id that the RP would like to assert. The U2F token will
     * enforce that the key handle provided above is associated with this
     * application id. The browser enforces that the calling origin belongs to the
     * application identified by the application id.
     */
    @JsonProperty
    @NonNull String appId;

    /**
     * websafe-base64 encoding of the key handle obtained from the U2F token
     * during registration.
     */
    @JsonProperty
    @NonNull String keyHandle;

    public String getRequestId() {
        return challenge;
    }

    public static SignRequest fromJson(String json) throws U2fBadInputException {
        return fromJson(json, SignRequest.class);
    }

    @JsonPOJOBuilder(withPrefix = "")
    public static class SignRequestBuilder {}
}
