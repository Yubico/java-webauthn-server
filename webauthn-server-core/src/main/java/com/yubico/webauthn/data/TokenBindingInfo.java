package com.yubico.webauthn.data;

import java.util.Optional;
import lombok.NonNull;
import lombok.Value;

@Value
public class TokenBindingInfo {

    private TokenBindingStatus status;
    private Optional<ByteArray> id;

    private TokenBindingInfo(TokenBindingStatus status) {
        this(status, Optional.empty());
    }

    public TokenBindingInfo(
        @NonNull TokenBindingStatus status,
        @NonNull Optional<ByteArray> id
    ) {
        this.status = status;
        this.id = id;
    }

    public static TokenBindingInfo present(ByteArray id) {
        return new TokenBindingInfo(TokenBindingStatus.PRESENT, Optional.of(id));
    }

    public static TokenBindingInfo supported() {
        return new TokenBindingInfo(TokenBindingStatus.SUPPORTED);
    }

    public static TokenBindingInfo notSupported() {
        return new TokenBindingInfo(TokenBindingStatus.NOT_SUPPORTED);
    }

}
