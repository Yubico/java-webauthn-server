package com.yubico.webauthn;

import com.fasterxml.jackson.databind.JsonNode;
import com.yubico.attestation.MetadataService;
import com.yubico.webauthn.data.AssertionRequest;
import com.yubico.webauthn.data.AssertionResult;
import com.yubico.webauthn.data.AttestationConveyancePreference;
import com.yubico.webauthn.data.AuthenticatorAssertionResponse;
import com.yubico.webauthn.data.AuthenticatorAttestationResponse;
import com.yubico.webauthn.data.AuthenticatorSelectionCriteria;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.FinishRegistrationOptions;
import com.yubico.webauthn.data.PublicKeyCredential;
import com.yubico.webauthn.data.PublicKeyCredentialCreationOptions;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;
import com.yubico.webauthn.data.PublicKeyCredentialParameters;
import com.yubico.webauthn.data.PublicKeyCredentialRequestOptions;
import com.yubico.webauthn.data.RegistrationResult;
import com.yubico.webauthn.data.RelyingPartyIdentity;
import com.yubico.webauthn.data.StartRegistrationOptions;
import com.yubico.webauthn.impl.BouncyCastleCrypto;
import com.yubico.webauthn.impl.FinishAssertionSteps;
import com.yubico.webauthn.impl.FinishRegistrationSteps;
import com.yubico.webauthn.impl.RandomChallengeGenerator;
import java.util.List;
import java.util.Optional;
import lombok.Builder;
import lombok.Value;


@Builder
@Value
public class RelyingParty {

    private final RelyingPartyIdentity rp;
    private final List<PublicKeyCredentialParameters> preferredPubkeyParams;
    private final List<String> origins;
    private final CredentialRepository credentialRepository;

    @Builder.Default
    private final ChallengeGenerator challengeGenerator = new RandomChallengeGenerator();
    @Builder.Default
    private final Crypto crypto = new BouncyCastleCrypto();
    @Builder.Default
    private final Optional<AttestationConveyancePreference> attestationConveyancePreference = Optional.empty();
    @Builder.Default
    private final Optional<MetadataService> metadataService = Optional.empty();
    @Builder.Default
    private final boolean allowMissingTokenBinding = false;
    @Builder.Default
    private final boolean allowUnrequestedExtensions = false;
    @Builder.Default
    private final boolean allowUntrustedAttestation = false;
    @Builder.Default
    private final boolean validateSignatureCounter = true;
    @Builder.Default
    private final boolean validateTypeAttribute = true;

    public PublicKeyCredentialCreationOptions startRegistration(StartRegistrationOptions startRegistrationOptions) {
        return PublicKeyCredentialCreationOptions.builder()
            .rp(rp)
            .user(startRegistrationOptions.getUser())
            .challenge(new ByteArray(challengeGenerator.generateChallenge()))
            .pubKeyCredParams(preferredPubkeyParams)
            .excludeCredentials(startRegistrationOptions.getExcludeCredentials())
            .authenticatorSelection(Optional.of(
                AuthenticatorSelectionCriteria.builder()
                    .requireResidentKey(startRegistrationOptions.isRequireResidentKey())
                    .build()
            ))
            .attestation(attestationConveyancePreference.orElse(AttestationConveyancePreference.DEFAULT))
            .extensions(startRegistrationOptions.getExtensions())
            .build();
    }

    public RegistrationResult finishRegistration(FinishRegistrationOptions finishRegistrationOptions) {
        return _finishRegistration(finishRegistrationOptions.getRequest(), finishRegistrationOptions.getResponse(), finishRegistrationOptions.getCallerTokenBindingId()).run();
    }

    /**
     * This method is NOT part of the public API.
     *
     * This method is called internally by {@link
     * #finishRegistration(FinishRegistrationOptions)}. It is a separate method to facilitate
     * testing; users should call {@link
     * #finishRegistration(FinishRegistrationOptions)} instead of this method.
     * @return
     */
    FinishRegistrationSteps _finishRegistration(
        PublicKeyCredentialCreationOptions request,
        PublicKeyCredential<AuthenticatorAttestationResponse> response,
        Optional<ByteArray> callerTokenBindingId
    ) {
        return FinishRegistrationSteps.builder()
            .request(request)
            .response(response)
            .callerTokenBindingId(callerTokenBindingId)
            .credentialRepository(credentialRepository)
            .origins(origins)
            .rpId(rp.getId())
            .crypto(crypto)
            .allowMissingTokenBinding(allowMissingTokenBinding)
            .allowUnrequestedExtensions(allowUnrequestedExtensions)
            .allowUntrustedAttestation(allowUntrustedAttestation)
            .metadataService(metadataService)
            .validateTypeAttribute(validateTypeAttribute)
            .build();
    }

    public AssertionRequest startAssertion(
        Optional<String> username,
        Optional<List<PublicKeyCredentialDescriptor>> allowCredentials, // = None.asJava
        Optional<JsonNode> extensions // = None.asJava
    ) {
        return AssertionRequest.builder()
            .username(username)
            .publicKeyCredentialRequestOptions(PublicKeyCredentialRequestOptions.builder()
                .rpId(Optional.of(rp.getId()))
                .challenge(new ByteArray(challengeGenerator.generateChallenge()))
                .allowCredentials(
                    (allowCredentials.map(Optional::of).orElseGet(() ->
                        username.map(un ->
                            credentialRepository.getCredentialIdsForUsername(un))
                    ))
                )
                .extensions(extensions)
                .build()
            )
            .build();
    }

    public AssertionResult finishAssertion(
        AssertionRequest request,
        PublicKeyCredential<AuthenticatorAssertionResponse> response,
        Optional<ByteArray> callerTokenBindingId // = None.asJava
    ) {
        return _finishAssertion(request, response, callerTokenBindingId).run();
    }

    /**
     * This method is NOT part of the public API.
     *
     * This method is called internally by {@link
     * #finishAssertion(AssertionRequest, PublicKeyCredential, Optional)}. It is
     * a separate method to facilitate testing; users should call {@link
     * #finishAssertion(AssertionRequest, PublicKeyCredential, Optional)}
     * instead of this method.
     */
    FinishAssertionSteps _finishAssertion(
        AssertionRequest request,
        PublicKeyCredential<AuthenticatorAssertionResponse> response,
        Optional<ByteArray> callerTokenBindingId // = None.asJava
    ) {
        return FinishAssertionSteps.builder()
            .request(request)
            .response(response)
            .callerTokenBindingId(callerTokenBindingId)
            .origins(origins)
            .rpId(rp.getId())
            .crypto(crypto)
            .credentialRepository(credentialRepository)
            .allowMissingTokenBinding(allowMissingTokenBinding)
            .allowUnrequestedExtensions(allowUnrequestedExtensions)
            .validateSignatureCounter(validateSignatureCounter)
            .validateTypeAttribute(validateTypeAttribute)
            .build();
    }

}
