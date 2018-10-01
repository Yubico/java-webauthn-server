package com.yubico.webauthn.data;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Optional;
import lombok.NonNull;
import lombok.Value;

import static com.yubico.internal.util.ExceptionUtil.assure;

@Value
public class TokenBindingInfo {

    @NonNull
    private final TokenBindingStatus status;

    @NonNull
    private final Optional<ByteArray> id;

    TokenBindingInfo(
        @NonNull TokenBindingStatus status,
        @NonNull Optional<ByteArray> id
    ) {
        if (status == TokenBindingStatus.PRESENT) {
            assure(
                id.isPresent(),
                "Token binding ID must be present if status is \"%s\".",
                TokenBindingStatus.PRESENT
            );
        } else {
            assure(
                !id.isPresent(),
                "Token binding ID must not be present if status is not \"%s\".",
                TokenBindingStatus.PRESENT
            );
        }

        this.status = status;
        this.id = id;
    }

    @JsonCreator
    private TokenBindingInfo(
        @NonNull @JsonProperty("status") TokenBindingStatus status,
        @JsonProperty("id") ByteArray id
    ) {
        this(status, Optional.ofNullable(id));
    }

    public static TokenBindingInfo present(@NonNull ByteArray id) {
        return new TokenBindingInfo(TokenBindingStatus.PRESENT, Optional.of(id));
    }

    public static TokenBindingInfo supported() {
        return new TokenBindingInfo(TokenBindingStatus.SUPPORTED, Optional.empty());
    }

    public static TokenBindingInfo notSupported() {
        return new TokenBindingInfo(TokenBindingStatus.NOT_SUPPORTED, Optional.empty());
    }

}
