package com.yubico.u2f.data.messages;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonPOJOBuilder;
import com.yubico.u2f.U2fPrimitives;
import com.yubico.u2f.data.messages.json.JsonSerializable;
import java.io.Serializable;
import java.util.Set;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.NonNull;
import lombok.Value;


@Value
@Builder
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonDeserialize(builder = RegisteredKey.RegisteredKeyBuilder.class)
public class RegisteredKey extends JsonSerializable implements Serializable {

    private static final long serialVersionUID = -5509788965855488374L;

    /**
     * Version of the protocol that the to-be-registered U2F token must speak. For
     * the version of the protocol described herein, must be "U2F_V2"
     */
    @NonNull
    String version;

    /**
     * websafe-base64 encoding of the key handle obtained from the U2F token
     * during registration.
     */
    @NonNull String keyHandle;

    String appId;
    Set<String> transports;

    public RegisteredKey(String keyHandle) {
        this(U2fPrimitives.U2F_VERSION, keyHandle, null, null);
    }

    @JsonPOJOBuilder(withPrefix = "")
    public static class RegisteredKeyBuilder {}
}
