package com.yubico.webauthn.data;

import java.util.Optional;
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
@Builder
public class AuthenticatorSelectionCriteria {

    /**
     * If present, eligible authenticators are filtered to only authenticators attached with the specified §4.4.4
     * Authenticator Attachment enumeration.
     */
    @Builder.Default
    private Optional<AuthenticatorAttachment> authenticatorAttachment = Optional.empty();

    /**
     * requireResidentKey Describes the Relying Party's requirements regarding availability of the Client-side-resident
     * Credential Private Key. If the parameter is set to true, the authenticator MUST create a Client-side-resident
     * Credential Private Key when creating a public key credential.
     */
    @Builder.Default
    private boolean requireResidentKey = false;

    /**
     * requireUserVerification
     * <p>
     * This member describes the Relying Party's requirements regarding user verification for the create() operation.
     * Eligible authenticators are filtered to only those capable of satisfying this requirement.
     */
    @Builder.Default
    private UserVerificationRequirement userVerification = UserVerificationRequirement.PREFERRED;

    public AuthenticatorSelectionCriteria(
        @NonNull Optional<AuthenticatorAttachment> authenticatorAttachment,
        boolean requireResidentKey,
        @NonNull UserVerificationRequirement userVerification
    ) {
        this.authenticatorAttachment = authenticatorAttachment;
        this.requireResidentKey = requireResidentKey;
        this.userVerification = userVerification;
    }
}
