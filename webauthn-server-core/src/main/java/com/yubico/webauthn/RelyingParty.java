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
import com.yubico.webauthn.data.AttestationConveyancePreference;
import com.yubico.webauthn.data.AuthenticatorAssertionResponse;
import com.yubico.webauthn.data.AuthenticatorAttestationResponse;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.ClientAssertionExtensionOutputs;
import com.yubico.webauthn.data.ClientRegistrationExtensionOutputs;
import com.yubico.webauthn.data.PublicKeyCredential;
import com.yubico.webauthn.data.PublicKeyCredentialCreationOptions;
import com.yubico.webauthn.data.PublicKeyCredentialCreationOptions.PublicKeyCredentialCreationOptionsBuilder;
import com.yubico.webauthn.data.PublicKeyCredentialParameters;
import com.yubico.webauthn.data.PublicKeyCredentialRequestOptions;
import com.yubico.webauthn.data.RelyingPartyIdentity;
import com.yubico.webauthn.exception.AssertionFailedException;
import com.yubico.webauthn.exception.RegistrationFailedException;
import com.yubico.webauthn.extension.appid.AppId;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import lombok.Builder;
import lombok.NonNull;
import lombok.Value;


@Builder(toBuilder = true)
@Value
public class RelyingParty {

    private static final SecureRandom random = new SecureRandom();

    @NonNull private final RelyingPartyIdentity identity;
    @NonNull private final List<String> origins;
    @NonNull private final CredentialRepository credentialRepository;

    @Builder.Default @NonNull private final Optional<AppId> appId = Optional.empty();
    @Builder.Default @NonNull private final Optional<AttestationConveyancePreference> attestationConveyancePreference = Optional.empty();
    @Builder.Default @NonNull private final Optional<MetadataService> metadataService = Optional.empty();
    @Builder.Default @NonNull private final List<PublicKeyCredentialParameters> preferredPubkeyParams = Collections.unmodifiableList(Arrays.asList(
        PublicKeyCredentialParameters.ES256,
        PublicKeyCredentialParameters.RS256
    ));
    @Builder.Default private final boolean allowMissingTokenBinding = false;
    @Builder.Default private final boolean allowUnrequestedExtensions = false;
    @Builder.Default private final boolean allowUntrustedAttestation = false;
    @Builder.Default private final boolean validateSignatureCounter = true;
    @Builder.Default private final boolean validateTypeAttribute = true;

    private RelyingParty(
        @NonNull RelyingPartyIdentity identity,
        List<String> origins,
        @NonNull CredentialRepository credentialRepository,
        @NonNull Optional<AppId> appId,
        @NonNull Optional<AttestationConveyancePreference> attestationConveyancePreference,
        @NonNull Optional<MetadataService> metadataService, List<PublicKeyCredentialParameters> preferredPubkeyParams,
        boolean allowMissingTokenBinding,
        boolean allowUnrequestedExtensions,
        boolean allowUntrustedAttestation,
        boolean validateSignatureCounter,
        boolean validateTypeAttribute
    ) {
        this.identity = identity;
        this.origins = origins != null ? origins : Collections.singletonList("https://" + identity.getId());
        this.credentialRepository = credentialRepository;
        this.appId = appId;
        this.attestationConveyancePreference = attestationConveyancePreference;
        this.metadataService = metadataService;
        this.preferredPubkeyParams = preferredPubkeyParams;
        this.allowMissingTokenBinding = allowMissingTokenBinding;
        this.allowUnrequestedExtensions = allowUnrequestedExtensions;
        this.allowUntrustedAttestation = allowUntrustedAttestation;
        this.validateSignatureCounter = validateSignatureCounter;
        this.validateTypeAttribute = validateTypeAttribute;
    }

    private static ByteArray generateChallenge() {
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        return new ByteArray(bytes);
    }

    public PublicKeyCredentialCreationOptions startRegistration(StartRegistrationOptions startRegistrationOptions) {
        PublicKeyCredentialCreationOptionsBuilder builder = PublicKeyCredentialCreationOptions.builder()
            .rp(identity)
            .user(startRegistrationOptions.getUser())
            .challenge(generateChallenge())
            .pubKeyCredParams(preferredPubkeyParams)
            .excludeCredentials(
                Optional.of(credentialRepository.getCredentialIdsForUsername(startRegistrationOptions.getUser().getName()))
            )
            .authenticatorSelection(startRegistrationOptions.getAuthenticatorSelection())
            .extensions(startRegistrationOptions.getExtensions())
        ;
        attestationConveyancePreference.ifPresent(builder::attestation);
        return builder.build();
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
            .allowMissingTokenBinding(allowMissingTokenBinding)
            .allowUnrequestedExtensions(allowUnrequestedExtensions)
            .allowUntrustedAttestation(allowUntrustedAttestation)
            .metadataService(metadataService)
            .validateTypeAttribute(validateTypeAttribute)
            .build();
    }

    public AssertionRequest startAssertion(StartAssertionOptions startAssertionOptions) {
        return AssertionRequest.builder()
            .publicKeyCredentialRequestOptions(
                PublicKeyCredentialRequestOptions.builder()
                    .challenge(generateChallenge())
                    .rpId(Optional.of(identity.getId()))
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
            .credentialRepository(credentialRepository)
            .allowMissingTokenBinding(allowMissingTokenBinding)
            .allowUnrequestedExtensions(allowUnrequestedExtensions)
            .validateSignatureCounter(validateSignatureCounter)
            .validateTypeAttribute(validateTypeAttribute)
            .build();
    }

    public static RelyingPartyBuilder.MandatoryStages builder() {
        return new RelyingPartyBuilder.MandatoryStages();
    }

    public static class RelyingPartyBuilder {
        public static class MandatoryStages {
            private final RelyingPartyBuilder builder = new RelyingPartyBuilder();

            public Step2 identity(RelyingPartyIdentity identity) {
                builder.identity(identity);
                return new Step2();
            }

            public class Step2 {
                public RelyingPartyBuilder credentialRepository(CredentialRepository credentialRepository) {
                    return builder.credentialRepository(credentialRepository);
                }
            }
        }
    }
}
