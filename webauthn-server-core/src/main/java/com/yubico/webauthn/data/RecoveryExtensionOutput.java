package com.yubico.webauthn.data;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import lombok.Builder;
import lombok.NonNull;
import lombok.Value;
import lombok.extern.slf4j.Slf4j;

@Value
@Builder
@Slf4j
public final class RecoveryExtensionOutput {

    @NonNull private final RecoveryExtensionAction action;
    private final int state;
    private final List<AttestedCredentialData> creds;
    private final ByteArray credId;
    private final ByteArray sig;

    @JsonCreator
    private RecoveryExtensionOutput(
        @NonNull @JsonProperty("action") RecoveryExtensionAction action,
        @JsonProperty("state") int state,
        @JsonProperty("creds") List<AttestedCredentialData> creds,
        @JsonProperty("credId") ByteArray credId,
        @JsonProperty("sig") ByteArray sig
    ) {
        this.action = action;
        this.state = state;
        this.creds = creds;
        this.credId = credId;
        this.sig = sig;
    }

    static Optional<RecoveryExtensionOutput> parse(CBORObject output) {
        if (output.getType() != CBORType.Map) {
            log.debug("Invalid type for recovery extension outputs; expected map, got: {}", output.getType());
            return Optional.empty();
        }

        RecoveryExtensionOutputBuilder builder = builder();

        final CBORObject actionCbor = output.get("action");
        if (actionCbor == null) {
            log.debug("Missing required \"action\" in {}", RecoveryExtensionOutput.class.getSimpleName());
            return Optional.empty();
        }
        if (actionCbor.getType() != CBORType.TextString) {
            log.debug("Invalid \"action\" type; expected text string, was: {}", actionCbor.getType());
            return Optional.empty();
        }
        final Optional<RecoveryExtensionAction> parsed = RecoveryExtensionAction.fromString(actionCbor.AsString());
        if (parsed.isPresent()) {
            builder.action(parsed.get());
        } else {
            log.debug("Unknown \"action\" value: {}", actionCbor.AsString());
            return Optional.empty();
        }
        final RecoveryExtensionAction action = parsed.get();

        {
            CBORObject state = output.get("state");
            if (state == null) {
                log.debug("Missing required \"state\" in {}", RecoveryExtensionOutput.class.getSimpleName());
                return Optional.empty();
            }
            if (!state.isIntegral()) {
                log.debug("Invalid \"state\" type; expected number, was: {}", state.getType());
                return Optional.empty();
            }
            if (!state.CanFitInInt32()) {
                log.debug("Value of \"state\" out of range: {}", state);
                return Optional.empty();
            }
            builder.state(state.AsInt32());
        }

        {
            CBORObject creds = output.get("creds");
            if (creds == null) {
                if (action == RecoveryExtensionAction.GENERATE) {
                    log.debug("Missing required \"creds\" for action: generate");
                    return Optional.empty();
                }
            } else {
                if (creds.getType() != CBORType.Array) {
                    log.debug("Invalid \"creds\" type; expected array, was: {}", creds.getType());
                    return Optional.empty();
                }
                try {
                    builder.creds(
                        creds.getValues().stream()
                            .map(credObject -> {
                                if (credObject.getType() != CBORType.ByteString) {
                                    log.debug("Invalid \"creds\" element type; expected byte string, was: {}", credObject.getType());
                                    throw new IllegalArgumentException(String.format(
                                        "Invalid \"creds\" element type; expected byte string, was: %s",
                                        credObject.getType()
                                    ));
                                }
                                final AttestedCredentialData.ParseResult parseResult =
                                    AttestedCredentialData.parse(credObject.GetByteString());
                                if (parseResult.remainingBytes.available() > 0) {
                                    log.debug("Unexpected bytes remaining after attested credential data: {}", parseResult.remainingBytes.available());
                                    throw new IllegalArgumentException(String.format(
                                        "Unexpected bytes remaining after attested credential data: %s", parseResult.remainingBytes.available()
                                    ));
                                }
                                return parseResult.attestedCredentialData;
                            })
                            .collect(Collectors.toList())
                    );
                } catch (IllegalArgumentException e) {
                    log.debug("Failed to parse \"creds\"", e);
                }
            }
        }

        {
            CBORObject credId = output.get("credId");
            if (credId == null) {
                if (action == RecoveryExtensionAction.RECOVER) {
                    log.debug("Missing required \"credId\" for action: recover");
                    return Optional.empty();
                }
            } else {
                if (credId.getType() != CBORType.ByteString) {
                    log.debug("Invalid \"credId\" type; expected byte string, was: {}", credId.getType());
                    return Optional.empty();
                }
                builder.credId(new ByteArray(credId.GetByteString()));
            }
        }

        {
            CBORObject sig = output.get("sig");
            if (sig == null) {
                if (action == RecoveryExtensionAction.RECOVER) {
                    log.debug("Missing required \"sig\" for action: recover");
                    return Optional.empty();
                }
            } else {
                if (sig.getType() != CBORType.ByteString) {
                    log.debug("Invalid \"sig\" type; expected byte string, was: {}", sig.getType());
                    return Optional.empty();
                }
                builder.sig(new ByteArray(sig.GetByteString()));
            }
        }

        return Optional.of(builder.build());
    }

    public Optional<List<AttestedCredentialData>> getCreds() {
        return Optional.ofNullable(creds);
    }

    public Optional<ByteArray> getCredId() {
        return Optional.ofNullable(credId);
    }

    public Optional<ByteArray> getSig() {
        return Optional.ofNullable(sig);
    }

    static RecoveryExtensionOutputBuilder builder() {
        return new RecoveryExtensionOutputBuilder();
    }

    static class RecoveryExtensionOutputBuilder {
    }

}
