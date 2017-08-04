package com.yubico.u2f.data.messages;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.common.base.Objects;
import com.yubico.u2f.U2fPrimitives;
import com.yubico.u2f.data.messages.json.JsonSerializable;
import com.yubico.u2f.data.messages.json.Persistable;
import com.yubico.u2f.exceptions.U2fBadInputException;
import java.io.Serializable;

import static com.google.common.base.Preconditions.checkNotNull;

public class RegisteredKey extends JsonSerializable implements Serializable {

    private static final long serialVersionUID = -5509788965855488374L;

    /**
     * Version of the protocol that the to-be-registered U2F token must speak. For
     * the version of the protocol described herein, must be "U2F_V2"
     */
    @JsonProperty
    private final String version = U2fPrimitives.U2F_VERSION;

    /**
     * websafe-base64 encoding of the key handle obtained from the U2F token
     * during registration.
     */
    @JsonProperty
    private final String keyHandle;

    @JsonCreator
    public RegisteredKey(@JsonProperty("keyHandle") String keyHandle) {
        this.keyHandle = checkNotNull(keyHandle);
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(keyHandle);
    }

    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof RegisteredKey))
            return false;
        RegisteredKey other = (RegisteredKey) obj;
        return Objects.equal(keyHandle, other.keyHandle)
                && Objects.equal(version, other.version);
    }

    public String getKeyHandle() {
        return keyHandle;
    }

    public static RegisteredKey fromJson(String json) throws U2fBadInputException {
        return fromJson(json, RegisteredKey.class);
    }

}
