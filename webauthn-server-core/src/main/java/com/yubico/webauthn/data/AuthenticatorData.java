package com.yubico.webauthn.data;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.upokecenter.cbor.CBORException;
import com.upokecenter.cbor.CBORObject;
import com.yubico.internal.util.BinaryUtil;
import com.yubico.internal.util.ExceptionUtil;
import com.yubico.internal.util.WebAuthnCodecs;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.Optional;
import lombok.NonNull;
import lombok.Value;


@Value
@JsonSerialize(using = AuthenticatorData.JsonSerializer.class)
public class AuthenticatorData {

    @NonNull
    private final ByteArray bytes;

    /**
     * The flags byte.
     */
    @NonNull
    private final transient AuthenticationDataFlags flags;

    /**
     * Attestation data, if present.
     * <p>
     * See ''§5.3.1 Attestation data'' of [[com.yubico.webauthn.VersionInfo]] for details.
     */
    @NonNull
    private final transient Optional<AttestationData> attestationData;

    /**
     * Extension-defined authenticator data, if present.
     * <p>
     * See ''§8 WebAuthn Extensions'' of [[com.yubico.webauthn.VersionInfo]] for details.
     */
    @NonNull
    private final transient Optional<CBORObject> extensions;

    private static final int RpIdHashLength = 32;
    private static final int FlagsLength = 1;
    private static final int CounterLength = 4;
    private static final int FixedLengthPartEndIndex = RpIdHashLength + FlagsLength + CounterLength;

    @JsonCreator
    public AuthenticatorData(@NonNull ByteArray bytes) {
        ExceptionUtil.assure(
            bytes.size() >= FixedLengthPartEndIndex,
            "%s byte array must be at least %d bytes, was %d: %s",
            AuthenticatorData.class.getSimpleName(),
            FixedLengthPartEndIndex,
            bytes.size(),
            bytes.getBase64Url()
        );

        this.bytes = bytes;

        final byte[] rawBytes = bytes.getBytes();

        this.flags = new AuthenticationDataFlags(rawBytes[32]);

        if (flags.AT) {
            VariableLengthParseResult parseResult = parseAttestationData(
                flags,
                Arrays.copyOfRange(rawBytes, FixedLengthPartEndIndex, rawBytes.length)
            );
            attestationData = parseResult.getAttestationData();
            extensions = parseResult.getExtensions();
        } else if (flags.ED) {
            attestationData = Optional.empty();
            extensions = Optional.of(parseExtensions(Arrays.copyOfRange(rawBytes, FixedLengthPartEndIndex, rawBytes.length)));
        } else {
            attestationData = Optional.empty();
            extensions = Optional.empty();
        }
    }

    /**
     * The SHA-256 hash of the RP ID associated with the credential.
     */
    @JsonProperty("rpIdHash")
    public ByteArray getRpIdHash() {
        return new ByteArray(Arrays.copyOfRange(bytes.getBytes(), 0, RpIdHashLength));
    }

    /**
     * The 32-bit unsigned signature counter.
     */
    public long getSignatureCounter() {
        final int start = RpIdHashLength + FlagsLength;
        final int end = start + CounterLength;
        return BinaryUtil.getUint32(Arrays.copyOfRange(bytes.getBytes(), start, end));
    }

    private static VariableLengthParseResult parseAttestationData(AuthenticationDataFlags flags, byte[] bytes) {
        byte[] credentialIdLengthBytes = Arrays.copyOfRange(bytes, 16, 16 + 2);

        final int L;
        try {
            L = BinaryUtil.getUint16(credentialIdLengthBytes);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Invalid credential ID length bytes: " + Arrays.asList(credentialIdLengthBytes), e);
        }

        ByteArrayInputStream indefiniteLengthBytes = new ByteArrayInputStream(
            Arrays.copyOfRange(bytes, 16 + 2 + L, bytes.length)
        );

        final CBORObject credentialPublicKey = CBORObject.Read(indefiniteLengthBytes);
        final Optional<CBORObject> extensions;

        if (flags.ED && indefiniteLengthBytes.available() > 0) {
            try {
                extensions = Optional.of(CBORObject.Read(indefiniteLengthBytes));
            } catch (CBORException e) {
                throw new IllegalArgumentException("Failed to parse extension data", e);
            }
        } else if (indefiniteLengthBytes.available() > 0) {
            throw new IllegalArgumentException(String.format(
                "Flags indicate no extension data, but %d bytes remain after attestation data.",
                indefiniteLengthBytes.available()
            ));
        } else if (flags.ED) {
            throw new IllegalArgumentException(
                "Flags indicate there should be extension data, but no bytes remain after attestation data."
            );
        } else {
            extensions = Optional.empty();
        }

        return new VariableLengthParseResult(
            Optional.of(AttestationData.builder()
                .aaguid(new ByteArray(Arrays.copyOfRange(bytes, 0, 16)))
                .credentialId(new ByteArray(Arrays.copyOfRange(bytes, 16 + 2, 16 + 2 + L)))
                .credentialPublicKey(new ByteArray(credentialPublicKey.EncodeToBytes()))
                .build()),
            extensions
        );
    }

    private static CBORObject parseExtensions(byte[] bytes) {
        try {
            return CBORObject.DecodeFromBytes(bytes);
        } catch (CBORException e) {
            throw new IllegalArgumentException("Failed to parse extension data", e);
        }
    }

    @Value
    private static class VariableLengthParseResult {
        Optional<AttestationData> attestationData;
        Optional<CBORObject> extensions;
    }

    public Optional<CBORObject> getExtensions() {
        return extensions.map(WebAuthnCodecs::deepCopy);
    }

    static class JsonSerializer extends com.fasterxml.jackson.databind.JsonSerializer<AuthenticatorData> {
        @Override
        public void serialize(AuthenticatorData value, JsonGenerator gen, SerializerProvider serializers) throws IOException {
            gen.writeString(value.getBytes().getBase64Url());
        }
    }

}
