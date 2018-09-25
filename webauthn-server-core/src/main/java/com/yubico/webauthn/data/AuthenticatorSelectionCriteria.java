package com.yubico.webauthn.data;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Optional;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.NonNull;
import lombok.Value;


/**
 * This class may be used to specify requirements regarding authenticator attributes.
 *
 * Note: The member identifiers are intentionally short, rather than descriptive, because they will be serialized into a
 * message to the authenticator, which may be sent over a low-bandwidth link.
 */
@Value
@AllArgsConstructor(access = AccessLevel.PRIVATE)
@Builder
public class AuthenticatorSelectionCriteria {

    /**
     * If present, eligible authenticators are filtered to only authenticators attached with the specified §4.4.4
     * Authenticator Attachment enumeration.
     */
    @NonNull
    @Builder.Default
    private final Optional<AuthenticatorAttachment> authenticatorAttachment = Optional.empty();

    /**
     * requireResidentKey Describes the Relying Party's requirements regarding availability of the Client-side-resident
     * Credential Private Key. If the parameter is set to true, the authenticator MUST create a Client-side-resident
     * Credential Private Key when creating a public key credential.
     */
    @Builder.Default
    private final boolean requireResidentKey = false;

    /**
     * requireUserVerification
     * <p>
     * This member describes the Relying Party's requirements regarding user verification for the create() operation.
     * Eligible authenticators are filtered to only those capable of satisfying this requirement.
     */
    @NonNull
    @Builder.Default
    private UserVerificationRequirement userVerification = UserVerificationRequirement.PREFERRED;

    @JsonCreator
    private AuthenticatorSelectionCriteria(
        @JsonProperty("authenticatorAttachment") AuthenticatorAttachment authenticatorAttachment,
        @JsonProperty("requireResidentKey") boolean requireResidentKey,
        @NonNull @JsonProperty("userVerification") UserVerificationRequirement userVerification
    ) {
        this(Optional.ofNullable(authenticatorAttachment), requireResidentKey, userVerification);
    }

}
