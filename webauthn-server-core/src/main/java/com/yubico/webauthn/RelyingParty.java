// Copyright (c) 2018, Yubico AB
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

package com.yubico.webauthn;

import com.yubico.webauthn.attestation.MetadataService;
import com.yubico.webauthn.data.AssertionRequest;
import com.yubico.webauthn.data.AssertionResult;
import com.yubico.webauthn.data.AttestationConveyancePreference;
import com.yubico.webauthn.data.AuthenticatorAssertionResponse;
import com.yubico.webauthn.data.AuthenticatorAttestationResponse;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.ClientAssertionExtensionOutputs;
import com.yubico.webauthn.data.ClientRegistrationExtensionOutputs;
import com.yubico.webauthn.data.PublicKeyCredential;
import com.yubico.webauthn.data.PublicKeyCredentialCreationOptions;
import com.yubico.webauthn.data.PublicKeyCredentialParameters;
import com.yubico.webauthn.data.PublicKeyCredentialRequestOptions;
import com.yubico.webauthn.data.RegistrationResult;
import com.yubico.webauthn.data.RelyingPartyIdentity;
import com.yubico.webauthn.exception.AssertionFailedException;
import com.yubico.webauthn.exception.RegistrationFailedException;
import com.yubico.webauthn.extension.appid.AppId;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.NonNull;
import lombok.Value;


@Builder
@AllArgsConstructor(access = AccessLevel.PRIVATE)
@Value
public class RelyingParty {

    @NonNull private final RelyingPartyIdentity identity;
    @NonNull private final List<PublicKeyCredentialParameters> preferredPubkeyParams;
    @NonNull private final List<String> origins;
    @NonNull private final CredentialRepository credentialRepository;

    @Builder.Default @NonNull private final Optional<AppId> appId = Optional.empty();
    @Builder.Default @NonNull private final ChallengeGenerator challengeGenerator = new RandomChallengeGenerator();
    @Builder.Default @NonNull private final Crypto crypto = new BouncyCastleCrypto();
    @Builder.Default @NonNull private final Optional<AttestationConveyancePreference> attestationConveyancePreference = Optional.empty();
    @Builder.Default @NonNull private final Optional<MetadataService> metadataService = Optional.empty();
    @Builder.Default private final boolean allowMissingTokenBinding = false;
    @Builder.Default private final boolean allowUnrequestedExtensions = false;
    @Builder.Default private final boolean allowUntrustedAttestation = false;
    @Builder.Default private final boolean validateSignatureCounter = true;
    @Builder.Default private final boolean validateTypeAttribute = true;

    public static RelyingPartyBuilder builder(
        @NonNull RelyingPartyIdentity identity,
        @NonNull List<PublicKeyCredentialParameters> preferredPubkeyParams,
        @NonNull List<String> origins,
        @NonNull CredentialRepository credentialRepository
    ) {
        return new RelyingPartyBuilder()
            .identity(identity)
            .preferredPubkeyParams(preferredPubkeyParams)
            .origins(origins)
            .credentialRepository(credentialRepository)
        ;
    }

    public PublicKeyCredentialCreationOptions startRegistration(StartRegistrationOptions startRegistrationOptions) {
        return PublicKeyCredentialCreationOptions.builder()
            .rp(identity)
            .user(startRegistrationOptions.getUser())
            .challenge(challengeGenerator.generateChallenge())
            .pubKeyCredParams(preferredPubkeyParams)
            .excludeCredentials(
                Optional.of(credentialRepository.getCredentialIdsForUsername(startRegistrationOptions.getUser().getName()))
            )
            .authenticatorSelection(startRegistrationOptions.getAuthenticatorSelection())
            .attestation(attestationConveyancePreference.orElse(AttestationConveyancePreference.DEFAULT))
            .extensions(startRegistrationOptions.getExtensions())
            .build();
    }

    public RegistrationResult finishRegistration(FinishRegistrationOptions finishRegistrationOptions) throws RegistrationFailedException {
        try {
            return _finishRegistration(finishRegistrationOptions.getRequest(), finishRegistrationOptions.getResponse(), finishRegistrationOptions.getCallerTokenBindingId()).run();
        } catch (IllegalArgumentException e) {
            throw new RegistrationFailedException(e);
        }
    }

    /**
     * This method is NOT part of the public API.
     *
     * This method is called internally by {@link
     * #finishRegistration(FinishRegistrationOptions)}. It is a separate method to facilitate
     * testing; users should call {@link
     * #finishRegistration(FinishRegistrationOptions)} instead of this method.
     */
    FinishRegistrationSteps _finishRegistration(
        PublicKeyCredentialCreationOptions request,
        PublicKeyCredential<AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs> response,
        Optional<ByteArray> callerTokenBindingId
    ) {
        return FinishRegistrationSteps.builder()
            .request(request)
            .response(response)
            .callerTokenBindingId(callerTokenBindingId)
            .credentialRepository(credentialRepository)
            .origins(origins)
            .rpId(identity.getId())
            .crypto(crypto)
            .allowMissingTokenBinding(allowMissingTokenBinding)
            .allowUnrequestedExtensions(allowUnrequestedExtensions)
            .allowUntrustedAttestation(allowUntrustedAttestation)
            .metadataService(metadataService)
            .validateTypeAttribute(validateTypeAttribute)
            .build();
    }

    public AssertionRequest startAssertion(StartAssertionOptions startAssertionOptions) {
        return AssertionRequest
            .builder(
                PublicKeyCredentialRequestOptions.builder()
                    .rpId(Optional.of(identity.getId()))
                    .challenge(challengeGenerator.generateChallenge())
                    .allowCredentials(
                        startAssertionOptions.getUsername().map(un ->
                            new ArrayList<>(credentialRepository.getCredentialIdsForUsername(un)))
                    )
                    .extensions(
                        startAssertionOptions.getExtensions()
                            .toBuilder()
                            .appid(appId)
                            .build()
                    )
                    .build()
            )
            .username(startAssertionOptions.getUsername())
            .build();
    }

    public AssertionResult finishAssertion(FinishAssertionOptions finishAssertionOptions) throws AssertionFailedException {
        try {
            return _finishAssertion(finishAssertionOptions.getRequest(), finishAssertionOptions.getResponse(), finishAssertionOptions.getCallerTokenBindingId()).run();
        } catch (IllegalArgumentException e) {
            throw new AssertionFailedException(e);
        }
    }

    /**
     * This method is NOT part of the public API.
     *
     * This method is called internally by {@link
     * #finishAssertion(FinishAssertionOptions)}. It is a separate method to
     * facilitate testing; users should call {@link
     * #finishAssertion(FinishAssertionOptions)} instead of this method.
     */
    FinishAssertionSteps _finishAssertion(
        AssertionRequest request,
        PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs> response,
        Optional<ByteArray> callerTokenBindingId // = None.asJava
    ) {
        return FinishAssertionSteps.builder()
            .request(request)
            .response(response)
            .callerTokenBindingId(callerTokenBindingId)
            .origins(origins)
            .rpId(identity.getId())
            .crypto(crypto)
            .credentialRepository(credentialRepository)
            .allowMissingTokenBinding(allowMissingTokenBinding)
            .allowUnrequestedExtensions(allowUnrequestedExtensions)
            .validateSignatureCounter(validateSignatureCounter)
            .validateTypeAttribute(validateTypeAttribute)
            .build();
    }

}
