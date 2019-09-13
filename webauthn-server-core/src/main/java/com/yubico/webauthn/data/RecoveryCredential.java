package com.yubico.webauthn.data;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;
import lombok.NonNull;
import lombok.Value;

/**
 * An abstraction of a recovery credential registered for a particular main credential.
 *
 * <p>
 * Instances of this class are not expected to be long-lived, and the library only needs to read them, never write them.
 * You may at your discretion store them directly in your database, or assemble them from other components.
 * </p>
 */
@Value
@Builder(toBuilder = true)
public class RecoveryCredential implements Comparable<RecoveryCredential> {

    /**
     * The AAGUID of the backup authenticator that owns this recovery credential.
     */
    @NonNull
    private final ByteArray aaguid;

    /**
     * The <a href="https://www.w3.org/TR/2019/PR-webauthn-20190117/#credential-id">credential ID</a> of the
     * credential.
     *
     * @see <a href="https://www.w3.org/TR/2019/PR-webauthn-20190117/#credential-id">Credential ID</a>
     * @see PublicKeyCredentialDescriptor#getId()
     */
    @NonNull
    private final ByteArray credentialId;

    /**
     * The <a href="https://www.w3.org/TR/2019/PR-webauthn-20190117/#credential-id">credential ID</a> of the
     * credential that is replaced if this one is used.
     *
     * @see <a href="https://www.w3.org/TR/2019/PR-webauthn-20190117/#credential-id">Credential ID</a>
     * @see PublicKeyCredentialDescriptor#getId()
     */
    @NonNull
    private final ByteArray replacesCredentialId;

    /**
     * The recovery credential public key encoded in COSE_Key format, as defined in Section 7 of <a
     * href="https://tools.ietf.org/html/rfc8152">RFC 8152</a>.
     *
     * <p>
     * This is used to verify the recovery signature in authentication assertions.
     * </p>
     *
     * @see AttestedCredentialData#getCredentialPublicKey()
     */
    @NonNull
    private final ByteArray publicKeyCose;

    @JsonCreator
    private RecoveryCredential(
        @NonNull @JsonProperty("aaguid") ByteArray aaguid,
        @NonNull @JsonProperty("credentialId") ByteArray credentialId,
        @NonNull @JsonProperty("replacesCredentialId") ByteArray replacesCredentialId,
        @NonNull @JsonProperty("publicKeyCose") ByteArray publicKeyCose
    ) {
        this.aaguid = aaguid;
        this.credentialId = credentialId;
        this.replacesCredentialId = replacesCredentialId;
        this.publicKeyCose = publicKeyCose;
    }

    @Override
    public int compareTo(RecoveryCredential other) {
        {
            final int comp = aaguid.compareTo(other.aaguid);
            if (comp != 0) {
                return comp;
            }
        }

        {
            final int comp = credentialId.compareTo(other.credentialId);
            if (comp != 0) {
                return comp;
            }
        }

        {
            final int comp = replacesCredentialId.compareTo(other.replacesCredentialId);
            if (comp != 0) {
                return comp;
            }
        }

        {
            final int comp = publicKeyCose.compareTo(other.publicKeyCose);
            if (comp != 0) {
                return comp;
            }
        }

        return 0;
    }

    public static RecoveryCredentialBuilder.MandatoryStages builder() {
        return new RecoveryCredentialBuilder.MandatoryStages();
    }

    public static class RecoveryCredentialBuilder {
        public static class MandatoryStages {
            private RecoveryCredentialBuilder builder = new RecoveryCredentialBuilder();
            public RecoveryCredentialBuilder.MandatoryStages.Step2 aaguid(ByteArray aaguid) {
                builder.aaguid(aaguid);
                return new RecoveryCredentialBuilder.MandatoryStages.Step2();
            }
            public class Step2 {
                public RecoveryCredentialBuilder.MandatoryStages.Step3 credentialId(ByteArray credentialId) {
                    builder.credentialId(credentialId);
                    return new RecoveryCredentialBuilder.MandatoryStages.Step3();
                }
            }
            public class Step3 {
                public RecoveryCredentialBuilder.MandatoryStages.Step4 replacesCredentialId(ByteArray userHandle) {
                    builder.replacesCredentialId(userHandle);
                    return new RecoveryCredentialBuilder.MandatoryStages.Step4();
                }
            }
            public class Step4 {
                public RecoveryCredentialBuilder publicKeyCose(ByteArray publicKeyCose) {
                    return builder.publicKeyCose(publicKeyCose);
                }
            }
        }
    }

}
