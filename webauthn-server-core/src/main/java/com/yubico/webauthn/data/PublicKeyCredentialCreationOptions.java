package com.yubico.webauthn.data;

import com.fasterxml.jackson.databind.JsonNode;
import com.yubico.util.ByteArray;
import com.yubico.webauthn.impl.util.WebAuthnCodecs;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import lombok.Builder;
import lombok.NonNull;
import lombok.Value;


@Value
@Builder(toBuilder = true)
public class PublicKeyCredentialCreationOptions {

    /**
     * Contains data about the Relying Party responsible for the request.
     */
    @NonNull
    private final RelyingPartyIdentity rp;

    /**
     * Contains data about the user account for which the Relying Party is requesting attestation.
     */
    @NonNull
    private final UserIdentity user;

    /**
     * A challenge intended to be used for generating the newly created credential’s attestation object.
     */
    @NonNull
    private final ByteArray challenge;

    /**
     * Information about the desired properties of the credential to be created.
     * <p>
     * The sequence is ordered from most preferred to least preferred. The client will make a best-effort to create the
     * most preferred credential that it can.
     */
    @NonNull
    private final List<PublicKeyCredentialParameters> pubKeyCredParams;

    /**
     * Specifies a time, in milliseconds, that the caller is willing to wait for the call to complete. This is treated
     * as a hint, and MAY be overridden by the platform.
     */
    @NonNull
    @Builder.Default
    private final Optional<Long> timeout = Optional.empty();

    /**
     * Intended for use by Relying Parties that wish to limit the creation of multiple credentials for the same account
     * on a single authenticator. The client is requested to return an error if the new credential would be created on
     * an authenticator that also contains one of the credentials enumerated in this parameter.
     */
    @NonNull
    @Builder.Default
    private final Optional<Collection<PublicKeyCredentialDescriptor>> excludeCredentials = Optional.empty();

    /**
     * Intended for use by Relying Parties that wish to select the appropriate authenticators to participate in the
     * create() operation.
     */
    @NonNull
    @Builder.Default
    private final Optional<AuthenticatorSelectionCriteria> authenticatorSelection = Optional.empty();

    /**
     * Intended for use by Relying Parties that wish to express their preference for attestation conveyance. The default
     * is none.
     */
    @NonNull
    @Builder.Default
    private final AttestationConveyancePreference attestation = AttestationConveyancePreference.DEFAULT;

    /**
     * Additional parameters requesting additional processing by the client and authenticator.
     * <p>
     * For example, the caller may request that only authenticators with certain capabilies be used to create the
     * credential, or that particular information be returned in the attestation object. Some extensions are defined in
     * §8 WebAuthn Extensions; consult the IANA "WebAuthn Extension Identifier" registry  for an up-to-date list of
     * registered WebAuthn Extensions.
     */
    @NonNull
    @Builder.Default
    private final Optional<JsonNode> extensions = Optional.empty();

    private PublicKeyCredentialCreationOptions(
        @NonNull RelyingPartyIdentity rp,
        @NonNull UserIdentity user,
        @NonNull ByteArray challenge,
        @NonNull List<PublicKeyCredentialParameters> pubKeyCredParams,
        @NonNull Optional<Long> timeout,
        @NonNull Optional<Collection<PublicKeyCredentialDescriptor>> excludeCredentials,
        @NonNull Optional<AuthenticatorSelectionCriteria> authenticatorSelection,
        @NonNull AttestationConveyancePreference attestation,
        @NonNull Optional<JsonNode> extensions
    ) {
        this.rp = rp;
        this.user = user;
        this.challenge = challenge;
        this.pubKeyCredParams = Collections.unmodifiableList(pubKeyCredParams);
        this.timeout = timeout;
        this.excludeCredentials = excludeCredentials.map(Collections::unmodifiableCollection);
        this.authenticatorSelection = authenticatorSelection;
        this.attestation = attestation;
        this.extensions = extensions.map(WebAuthnCodecs::deepCopy);
    }

    public Optional<JsonNode> getExtensions() {
        return this.extensions.map(WebAuthnCodecs::deepCopy);
    }

}
