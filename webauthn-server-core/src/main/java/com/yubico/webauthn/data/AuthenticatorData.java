package com.yubico.webauthn.data;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.upokecenter.cbor.CBORException;
import com.upokecenter.cbor.CBORObject;
import com.yubico.u2f.data.messages.key.util.U2fB64Encoding;
import com.yubico.webauthn.util.BinaryUtil;
import com.yubico.webauthn.util.WebAuthnCodecs;
import java.io.ByteArrayInputStream;
import java.util.Arrays;
import java.util.Optional;
import lombok.Value;


@Value
public class AuthenticatorData {

    @JsonIgnore
    private final byte[] bytes;

    /**
     * The flags byte.
     */
    private final AuthenticationDataFlags flags;

    /**
     * Attestation data, if present.
     * <p>
     * See ''§5.3.1 Attestation data'' of [[com.yubico.webauthn.VersionInfo]] for details.
     */
    private final Optional<AttestationData> attestationData;

    /**
     * Extension-defined authenticator data, if present.
     * <p>
     * See ''§8 WebAuthn Extensions'' of [[com.yubico.webauthn.VersionInfo]] for details.
     */
    private final Optional<CBORObject> extensions;

    private static final int RpIdHashLength = 32;
    private static final int FlagsLength = 1;
    private static final int CounterLength = 4;
    private static final int FixedLengthPartEndIndex = RpIdHashLength + FlagsLength + CounterLength;

    public AuthenticatorData(byte[] bytes) {
        this.bytes = BinaryUtil.copy(bytes);
        this.flags = new AuthenticationDataFlags(bytes[32]);

        if (flags.AT) {
            VariableLengthParseResult parseResult = parseAttestationData(
                flags,
                Arrays.copyOfRange(bytes, FixedLengthPartEndIndex, bytes.length)
            );
            attestationData = parseResult.getAttestationData();
            extensions = parseResult.getExtensions();
        } else if (flags.ED) {
            attestationData = Optional.empty();
            extensions = Optional.of(parseExtensions(Arrays.copyOfRange(bytes, FixedLengthPartEndIndex, bytes.length)));
        } else {
            attestationData = Optional.empty();
            extensions = Optional.empty();
        }
    }

    public byte[] getBytes() {
        return BinaryUtil.copy(bytes);
    }

    @JsonProperty("authData")
    public String getAuthDataBase64() {
        return U2fB64Encoding.encode(bytes);
    }

    /**
     * The SHA-256 hash of the RP ID associated with the credential.
     */
    @JsonIgnore
    public byte[] getRpIdHash() {
        return Arrays.copyOfRange(bytes, 0, RpIdHashLength);
    }

    @JsonProperty("rpIdHash")
    public String getRpIdHashBase64() {
        return U2fB64Encoding.encode(getRpIdHash());
    }

    /**
     * The 32-bit unsigned signature counter.
     */
    public long getSignatureCounter() {
        final int start = RpIdHashLength + FlagsLength;
        final int end = start + CounterLength;
        return BinaryUtil.getUint32(Arrays.copyOfRange(bytes, start, end));
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
                .aaguid(Arrays.copyOfRange(bytes, 0, 16))
                .credentialId(Arrays.copyOfRange(bytes, 16 + 2, 16 + 2 + L))
                .credentialPublicKey(credentialPublicKey.EncodeToBytes())
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

}
