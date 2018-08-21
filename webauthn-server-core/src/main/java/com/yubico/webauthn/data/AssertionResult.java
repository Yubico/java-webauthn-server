package com.yubico.webauthn.data;

import java.util.Collections;
import java.util.List;
import lombok.Builder;
import lombok.NonNull;
import lombok.Value;


@Value
@Builder
public class AssertionResult {

    private final ByteArray credentialId;
    private final ByteArray userHandle;

    private final long signatureCount;
    private final boolean signatureCounterValid;
    private final boolean success;
    private final String username;
    private final List<String> warnings;

    private AssertionResult(
        @NonNull ByteArray credentialId,
        @NonNull ByteArray userHandle,
        long signatureCount,
        boolean signatureCounterValid,
        boolean success,
        @NonNull String username,
        @NonNull List<String> warnings
    ) {
        this.credentialId = credentialId;
        this.userHandle = userHandle;
        this.signatureCount = signatureCount;
        this.signatureCounterValid = signatureCounterValid;
        this.success = success;
        this.username = username;
        this.warnings = Collections.unmodifiableList(warnings);
    }

}

