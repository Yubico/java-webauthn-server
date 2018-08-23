package com.yubico.webauthn.data;

import com.yubico.u2f.data.messages.key.util.U2fB64Encoding;
import com.yubico.webauthn.util.BinaryUtil;
import java.security.PublicKey;
import lombok.NonNull;
import lombok.Value;


@Value
public class RegisteredCredential {

    private byte[] credentialId;
    private byte[] userHandle;

    public final PublicKey publicKey;
    public final long signatureCount;

    public RegisteredCredential(
        @NonNull byte[] credentialId,
        @NonNull byte[] userHandle,
        @NonNull PublicKey publicKey,
        long signatureCount
    ) {
        this.credentialId = BinaryUtil.copy(credentialId);
        this.userHandle = BinaryUtil.copy(userHandle);
        this.publicKey = publicKey;
        this.signatureCount = signatureCount;
    }

    public byte[] getCredentialId() {
        return BinaryUtil.copy(credentialId);
    }

    public byte[] getUserHandle() {
        return BinaryUtil.copy(userHandle);
    }

    public String getUserHandleBase64() {
        return U2fB64Encoding.encode(userHandle);
    }

}
