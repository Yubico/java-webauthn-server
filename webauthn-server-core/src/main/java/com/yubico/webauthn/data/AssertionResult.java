package com.yubico.webauthn.data;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Collections;
import java.util.List;
import lombok.Builder;
import lombok.NonNull;
import lombok.Value;


@Value
@Builder
public class AssertionResult {

    @NonNull
    private final ByteArray credentialId;

    @NonNull
    private final ByteArray userHandle;

    private final long signatureCount;

    private final boolean signatureCounterValid;

    private final boolean success;

    @NonNull
    private final String username;

    @NonNull
    private final List<String> warnings;

    @JsonCreator
    private AssertionResult(
        @NonNull @JsonProperty("credentialId") ByteArray credentialId,
        @NonNull @JsonProperty("userHandle") ByteArray userHandle,
        @JsonProperty("signatureCount") long signatureCount,
        @JsonProperty("signatureCounterValid") boolean signatureCounterValid,
        @JsonProperty("success") boolean success,
        @NonNull @JsonProperty("username") String username,
        @NonNull @JsonProperty("warnings") List<String> warnings
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

