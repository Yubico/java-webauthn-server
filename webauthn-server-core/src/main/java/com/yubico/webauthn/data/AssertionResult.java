package com.yubico.webauthn.data;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.yubico.u2f.data.messages.key.util.U2fB64Encoding;
import com.yubico.webauthn.util.BinaryUtil;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import lombok.Builder;
import lombok.NonNull;
import lombok.Value;


@Value
@Builder
public class AssertionResult {

    @JsonIgnore
    private final byte[] credentialId;
    @JsonIgnore
    private final byte[] userHandle;

    private final long signatureCount;
    private final boolean signatureCounterValid;
    private final boolean success;
    private final String username;
    private final List<String> warnings;

    AssertionResult(
        @NonNull byte[] credentialId,
        @NonNull byte[] userHandle,
        long signatureCount,
        boolean signatureCounterValid,
        boolean success,
        @NonNull String username,
        @NonNull List<String> warnings
    ) {
        this.credentialId = BinaryUtil.copy(credentialId);
        this.userHandle = BinaryUtil.copy(userHandle);
        this.signatureCount = signatureCount;
        this.signatureCounterValid = signatureCounterValid;
        this.success = success;
        this.username = username;
        this.warnings = Collections.unmodifiableList(warnings);
    }

    @JsonProperty("credentialId")
    public String getCredentialIdBase64() {
        return U2fB64Encoding.encode(credentialId);
    }

    @JsonProperty("userHandle")
    public String getUserHandleBase64() {
        return U2fB64Encoding.encode(userHandle);
    }

    public byte[] getCredentialId() {
        return BinaryUtil.copy(credentialId);
    }

    public byte[] getUserHandle() {
        return BinaryUtil.copy(userHandle);
    }
}

