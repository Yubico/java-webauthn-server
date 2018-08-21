package com.yubico.webauthn.data;

import java.security.PublicKey;
import lombok.Value;


@Value
public class RegisteredCredential {

    private ByteArray credentialId;
    private ByteArray userHandle;

    public final PublicKey publicKey;
    public final long signatureCount;

}
