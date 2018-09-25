package com.yubico.webauthn;

import com.yubico.webauthn.data.ByteArray;
import java.security.PublicKey;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.NonNull;
import lombok.Value;


@Value
@AllArgsConstructor(access = AccessLevel.PRIVATE)
@Builder
public class RegisteredCredential {

    @NonNull
    private final ByteArray credentialId;

    @NonNull
    private final ByteArray userHandle;

    @NonNull
    public final PublicKey publicKey;

    public final long signatureCount;

}
