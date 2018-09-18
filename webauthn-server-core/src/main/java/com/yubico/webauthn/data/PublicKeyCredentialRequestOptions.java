package com.yubico.webauthn.data;

import com.fasterxml.jackson.databind.JsonNode;
import com.yubico.webauthn.internal.WebAuthnCodecs;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import lombok.Builder;
import lombok.NonNull;
import lombok.Value;


/**
 * The PublicKeyCredentialRequestOptions dictionary supplies get() with the data it needs to generate an assertion.
 * <p>
 * Its `challenge` member must be present, while its other members are optional.
 */
@Value
@Builder
public class PublicKeyCredentialRequestOptions {

    /**
     * A challenge that the selected authenticator signs, along with other data, when producing an authentication
     * assertion.
     */
    @NonNull
    private final ByteArray challenge;

    /**
     * Specifies a time, in milliseconds, that the caller is willing to wait for the call to complete.
     * <p>
     * This is treated as a hint, and MAY be overridden by the platform.
     */
    @NonNull
    @Builder.Default
    private final Optional<Long> timeout = Optional.empty();

    /**
     * Specifies the relying party identifier claimed by the caller.
     * <p>
     * If omitted, its value will be set by the client.
     */
    @NonNull
    @Builder.Default
    private final Optional<String> rpId = Optional.empty();

    /**
     * A list of public key credentials acceptable to the caller, in descending order of the caller’s preference.
     */
    @NonNull
    @Builder.Default
    private final Optional<List<PublicKeyCredentialDescriptor>> allowCredentials = Optional.empty();

    /**
     * Describes the Relying Party's requirements regarding user verification for the get() operation.
     * <p>
     * Eligible authenticators are filtered to only those capable of satisfying this requirement.
     */
    @NonNull
    @Builder.Default
    private final UserVerificationRequirement userVerification = UserVerificationRequirement.DEFAULT;

    /**
     * Additional parameters requesting additional processing by the client and authenticator.
     * <p>
     * For example, if transaction confirmation is sought from the user, then the prompt string might be included as an
     * extension.
     */
    @NonNull
    @Builder.Default
    private final Optional<JsonNode> extensions = Optional.empty();

    PublicKeyCredentialRequestOptions(
        @NonNull ByteArray challenge,
        @NonNull Optional<Long> timeout,
        @NonNull Optional<String> rpId,
        @NonNull Optional<List<PublicKeyCredentialDescriptor>> allowCredentials,
        @NonNull UserVerificationRequirement userVerification,
        @NonNull Optional<JsonNode> extensions
    ) {
        this.challenge = challenge;
        this.timeout = timeout;
        this.rpId = rpId;
        this.allowCredentials = allowCredentials.map(Collections::unmodifiableList);
        this.userVerification = userVerification;
        this.extensions = extensions.map(WebAuthnCodecs::deepCopy);
    }

    public Optional<JsonNode> getExtensions() {
        return this.extensions.map(WebAuthnCodecs::deepCopy);
    }

}
