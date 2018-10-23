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

    private static final int RP_ID_HASH_INDEX = 0;
    private static final int RP_ID_HASH_END = RP_ID_HASH_INDEX + 32;

    private static final int FLAGS_INDEX = RP_ID_HASH_END;
    private static final int FLAGS_END = FLAGS_INDEX + 1;

    private static final int COUNTER_INDEX = FLAGS_END;
    private static final int COUNTER_END = COUNTER_INDEX + 4;

    private static final int FIXED_LENGTH_PART_END_INDEX = COUNTER_END;

    @JsonCreator
    public AuthenticatorData(@NonNull ByteArray bytes) {
        ExceptionUtil.assure(
            bytes.size() >= FIXED_LENGTH_PART_END_INDEX,
            "%s byte array must be at least %d bytes, was %d: %s",
            AuthenticatorData.class.getSimpleName(),
            FIXED_LENGTH_PART_END_INDEX,
            bytes.size(),
            bytes.getBase64Url()
        );

        this.bytes = bytes;

        final byte[] rawBytes = bytes.getBytes();

        this.flags = new AuthenticationDataFlags(rawBytes[FLAGS_INDEX]);

        if (flags.AT) {
            VariableLengthParseResult parseResult = parseAttestationData(
                flags,
                Arrays.copyOfRange(rawBytes, FIXED_LENGTH_PART_END_INDEX, rawBytes.length)
            );
            attestationData = parseResult.getAttestationData();
            extensions = parseResult.getExtensions();
        } else if (flags.ED) {
            attestationData = Optional.empty();
            extensions = Optional.of(parseExtensions(Arrays.copyOfRange(rawBytes, FIXED_LENGTH_PART_END_INDEX, rawBytes.length)));
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
        return new ByteArray(Arrays.copyOfRange(bytes.getBytes(), RP_ID_HASH_INDEX, RP_ID_HASH_END));
    }

    /**
     * The 32-bit unsigned signature counter.
     */
    public long getSignatureCounter() {
        return BinaryUtil.getUint32(Arrays.copyOfRange(bytes.getBytes(), COUNTER_INDEX, COUNTER_END));
    }

    private static VariableLengthParseResult parseAttestationData(AuthenticationDataFlags flags, byte[] bytes) {
        final int AAGUID_INDEX = 0;
        final int AAGUID_END = AAGUID_INDEX + 16;

        final int CREDENTIAL_ID_LENGTH_INDEX = AAGUID_END;
        final int CREDENTIAL_ID_LENGTH_END = CREDENTIAL_ID_LENGTH_INDEX + 2;

        byte[] credentialIdLengthBytes = Arrays.copyOfRange(bytes, CREDENTIAL_ID_LENGTH_INDEX, CREDENTIAL_ID_LENGTH_END);

        final int L;
        try {
            L = BinaryUtil.getUint16(credentialIdLengthBytes);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Invalid credential ID length bytes: " + Arrays.asList(credentialIdLengthBytes), e);
        }

        final int CREDENTIAL_ID_INDEX = CREDENTIAL_ID_LENGTH_END;
        final int CREDENTIAL_ID_END = CREDENTIAL_ID_INDEX + L;

        final int CREDENTIAL_PUBLIC_KEY_INDEX = CREDENTIAL_ID_END;
        final int CREDENTIAL_PUBLIC_KEY_AND_EXTENSION_DATA_END = bytes.length;

        ByteArrayInputStream indefiniteLengthBytes = new ByteArrayInputStream(
            Arrays.copyOfRange(bytes, CREDENTIAL_PUBLIC_KEY_INDEX, CREDENTIAL_PUBLIC_KEY_AND_EXTENSION_DATA_END)
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
                .aaguid(new ByteArray(Arrays.copyOfRange(bytes, AAGUID_INDEX, AAGUID_END)))
                .credentialId(new ByteArray(Arrays.copyOfRange(bytes, CREDENTIAL_ID_INDEX, CREDENTIAL_ID_END)))
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
