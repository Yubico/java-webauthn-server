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

import com.yubico.internal.util.CollectionUtil;
import com.yubico.internal.util.OptionalUtil;
import com.yubico.webauthn.attestation.MetadataService;
import com.yubico.webauthn.data.AssertionExtensionInputs;
import com.yubico.webauthn.data.AttestationConveyancePreference;
import com.yubico.webauthn.data.AuthenticatorAssertionResponse;
import com.yubico.webauthn.data.AuthenticatorAttestationResponse;
import com.yubico.webauthn.data.AuthenticatorData;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.ClientAssertionExtensionOutputs;
import com.yubico.webauthn.data.ClientRegistrationExtensionOutputs;
import com.yubico.webauthn.data.CollectedClientData;
import com.yubico.webauthn.data.PublicKeyCredential;
import com.yubico.webauthn.data.PublicKeyCredentialCreationOptions;
import com.yubico.webauthn.data.PublicKeyCredentialCreationOptions.PublicKeyCredentialCreationOptionsBuilder;
import com.yubico.webauthn.data.PublicKeyCredentialParameters;
import com.yubico.webauthn.data.PublicKeyCredentialRequestOptions;
import com.yubico.webauthn.data.PublicKeyCredentialRequestOptions.PublicKeyCredentialRequestOptionsBuilder;
import com.yubico.webauthn.data.RegistrationExtensionInputs;
import com.yubico.webauthn.data.RelyingPartyIdentity;
import com.yubico.webauthn.exception.AssertionFailedException;
import com.yubico.webauthn.exception.InvalidSignatureCountException;
import com.yubico.webauthn.exception.RegistrationFailedException;
import com.yubico.webauthn.extension.appid.AppId;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import lombok.Builder;
import lombok.NonNull;
import lombok.Value;
import lombok.extern.slf4j.Slf4j;

/**
 * Encapsulates the four basic Web Authentication operations - start/finish registration,
 * start/finish authentication - along with overall operational settings for them.
 *
 * <p>This class has no mutable state. An instance of this class may therefore be thought of as a
 * container for specialized versions (function closures) of these four operations rather than a
 * stateful object.
 */
@Slf4j
@Builder(toBuilder = true)
@Value
public class RelyingParty {

  private static final SecureRandom random = new SecureRandom();

  /**
   * The {@link RelyingPartyIdentity} that will be set as the {@link
   * PublicKeyCredentialCreationOptions#getRp() rp} parameter when initiating registration
   * operations, and which {@link AuthenticatorData#getRpIdHash()} will be compared against. This is
   * a required parameter.
   *
   * <p>A successful registration or authentication operation requires {@link
   * AuthenticatorData#getRpIdHash()} to exactly equal the SHA-256 hash of this member's {@link
   * RelyingPartyIdentity#getId() id} member. Alternatively, it may instead equal the SHA-256 hash
   * of {@link #getAppId() appId} if the latter is present.
   *
   * @see #startRegistration(StartRegistrationOptions)
   * @see PublicKeyCredentialCreationOptions
   */
  @NonNull private final RelyingPartyIdentity identity;

  /**
   * The allowed origins that returned authenticator responses will be compared against.
   *
   * <p>The default is the set containing only the string <code>
   * "https://" + {@link #getIdentity()}.getId()</code>.
   *
   * <p>If {@link RelyingPartyBuilder#allowOriginPort(boolean) allowOriginPort} and {@link
   * RelyingPartyBuilder#allowOriginSubdomain(boolean) allowOriginSubdomain} are both <code>false
   * </code> (the default), then a successful registration or authentication operation requires
   * {@link CollectedClientData#getOrigin()} to exactly equal one of these values.
   *
   * <p>If {@link RelyingPartyBuilder#allowOriginPort(boolean) allowOriginPort} is <code>true</code>
   * , then the above rule is relaxed to allow any port number in {@link
   * CollectedClientData#getOrigin()}, regardless of any port specified.
   *
   * <p>If {@link RelyingPartyBuilder#allowOriginSubdomain(boolean) allowOriginSubdomain} is <code>
   * true</code>, then the above rule is relaxed to allow any subdomain, of any depth, of any of
   * these values.
   *
   * <p>For either of the above relaxations to take effect, both the allowed origin and the client
   * data origin must be valid URLs. Origins that are not valid URLs are matched only by exact
   * string equality.
   *
   * @see #getIdentity()
   */
  @NonNull private final Set<String> origins;

  /**
   * An abstract database which can look up credentials, usernames and user handles from usernames,
   * user handles and credential IDs. This is a required parameter.
   *
   * <p>This is used to look up:
   *
   * <ul>
   *   <li>the user handle for a user logging in via user name
   *   <li>the user name for a user logging in via user handle
   *   <li>the credential IDs to include in {@link
   *       PublicKeyCredentialCreationOptions#getExcludeCredentials()}
   *   <li>the credential IDs to include in {@link
   *       PublicKeyCredentialRequestOptions#getAllowCredentials()}
   *   <li>that the correct user owns the credential when verifying an assertion
   *   <li>the public key to use to verify an assertion
   *   <li>the stored signature counter when verifying an assertion
   * </ul>
   */
  @NonNull private final CredentialRepository credentialRepository;

  /**
   * The extension input to set for the <code>appid</code> and <code>appidExclude</code> extensions.
   *
   * <p>You do not need this extension if you have not previously supported U2F. Its purpose is to
   * make already-registered U2F credentials forward-compatible with the WebAuthn API. It is not
   * needed for new registrations, even of U2F authenticators.
   *
   * <p>If this member is set, {@link #startAssertion(StartAssertionOptions) startAssertion} will
   * automatically set the <code>appid</code> extension input, and {@link
   * #finishAssertion(FinishAssertionOptions) finishAssertion} will adjust its verification logic to
   * also accept this AppID as an alternative to the RP ID. Likewise, {@link
   * #startRegistration(StartRegistrationOptions)} startRegistration} will automatically set the
   * <code>appidExclude</code> extension input.
   *
   * <p>By default, this is not set.
   *
   * @see AssertionExtensionInputs#getAppid()
   * @see RegistrationExtensionInputs#getAppidExclude()
   * @see <a href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-appid-extension">§10.1.
   *     FIDO AppID Extension (appid)</a>
   * @see <a
   *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-appid-exclude-extension">§10.2.
   *     FIDO AppID Exclusion Extension (appidExclude)</a>
   */
  @NonNull private final Optional<AppId> appId;

  /**
   * The argument for the {@link PublicKeyCredentialCreationOptions#getAttestation() attestation}
   * parameter in registration operations.
   *
   * <p>Unless your application has a concrete policy for authenticator attestation, it is
   * recommended to leave this parameter undefined.
   *
   * <p>If you set this, you may want to explicitly set {@link
   * RelyingPartyBuilder#allowUntrustedAttestation(boolean) allowUntrustedAttestation} and {@link
   * RelyingPartyBuilder#metadataService(MetadataService) metadataService} too.
   *
   * <p>By default, this is not set.
   *
   * @see PublicKeyCredentialCreationOptions#getAttestation()
   * @see <a href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-attestation">§6.4.
   *     Attestation</a>
   */
  @NonNull private final Optional<AttestationConveyancePreference> attestationConveyancePreference;

  /**
   * A {@link MetadataService} instance to use for looking up device attestation metadata. This
   * matters only if {@link #getAttestationConveyancePreference()} is non-empty and not set to
   * {@link AttestationConveyancePreference#NONE}.
   *
   * <p>By default, this is not set.
   *
   * @see PublicKeyCredentialCreationOptions#getAttestation()
   * @see <a href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-attestation">§6.4.
   *     Attestation</a>
   */
  @NonNull private final Optional<MetadataService> metadataService;

  /**
   * The argument for the {@link PublicKeyCredentialCreationOptions#getPubKeyCredParams()
   * pubKeyCredParams} parameter in registration operations.
   *
   * <p>This is a list of acceptable public key algorithms and their parameters, ordered from most
   * to least preferred.
   *
   * <p>The default is the following list:
   *
   * <ol>
   *   <li>{@link com.yubico.webauthn.data.PublicKeyCredentialParameters#ES256 ES256}
   *   <li>{@link com.yubico.webauthn.data.PublicKeyCredentialParameters#EdDSA EdDSA}
   *   <li>{@link com.yubico.webauthn.data.PublicKeyCredentialParameters#RS256 RS256}
   * </ol>
   *
   * @see PublicKeyCredentialCreationOptions#getAttestation()
   * @see <a href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-attestation">§6.4.
   *     Attestation</a>
   */
  @Builder.Default @NonNull
  private final List<PublicKeyCredentialParameters> preferredPubkeyParams =
      Collections.unmodifiableList(
          Arrays.asList(
              PublicKeyCredentialParameters.ES256,
              PublicKeyCredentialParameters.EdDSA,
              PublicKeyCredentialParameters.RS256));

  /**
   * If <code>true</code>, the origin matching rule is relaxed to allow any port number.
   *
   * <p>The default is <code>false</code>.
   *
   * <p>Examples with <code>
   * origins: ["https://example.org", "https://accounts.example.org", "https://acme.com:8443"]
   * </code>
   *
   * <ul>
   *   <li>
   *       <p><code>allowOriginPort: false</code>
   *       <p>Accepted:
   *       <ul>
   *         <li><code>https://example.org</code>
   *         <li><code>https://accounts.example.org</code>
   *         <li><code>https://acme.com:8443</code>
   *       </ul>
   *       <p>Rejected:
   *       <ul>
   *         <li><code>https://example.org:8443</code>
   *         <li><code>https://shop.example.org</code>
   *         <li><code>https://acme.com</code>
   *         <li><code>https://acme.com:9000</code>
   *       </ul>
   *   <li>
   *       <p><code>allowOriginPort: true</code>
   *       <p>Accepted:
   *       <ul>
   *         <li><code>https://example.org</code>
   *         <li><code>https://example.org:8443</code>
   *         <li><code>https://accounts.example.org</code>
   *         <li><code>https://acme.com</code>
   *         <li><code>https://acme.com:8443</code>
   *         <li><code>https://acme.com:9000</code>
   *       </ul>
   *       <p>Rejected:
   *       <ul>
   *         <li><code>https://shop.example.org</code>
   *       </ul>
   * </ul>
   */
  @Builder.Default private final boolean allowOriginPort = false;

  /**
   * If <code>true</code>, the origin matching rule is relaxed to allow any subdomain, of any depth,
   * of the values of {@link RelyingPartyBuilder#origins(Set) origins}.
   *
   * <p>The default is <code>false</code>.
   *
   * <p>Examples with <code>origins: ["https://example.org", "https://acme.com:8443"]</code>
   *
   * <ul>
   *   <li>
   *       <p><code>allowOriginSubdomain: false</code>
   *       <p>Accepted:
   *       <ul>
   *         <li><code>https://example.org</code>
   *         <li><code>https://acme.com:8443</code>
   *       </ul>
   *       <p>Rejected:
   *       <ul>
   *         <li><code>https://example.org:8443</code>
   *         <li><code>https://accounts.example.org</code>
   *         <li><code>https://acme.com</code>
   *         <li><code>https://eu.shop.acme.com:8443</code>
   *       </ul>
   *   <li>
   *       <p><code>allowOriginSubdomain: true</code>
   *       <p>Accepted:
   *       <ul>
   *         <li><code>https://example.org</code>
   *         <li><code>https://accounts.example.org</code>
   *         <li><code>https://acme.com:8443</code>
   *         <li><code>https://eu.shop.acme.com:8443</code>
   *       </ul>
   *       <p>Rejected:
   *       <ul>
   *         <li><code>https://example.org:8443</code>
   *         <li><code>https://acme.com</code>
   *       </ul>
   * </ul>
   */
  @Builder.Default private final boolean allowOriginSubdomain = false;

  /**
   * If <code>true</code>, {@link #finishRegistration(FinishRegistrationOptions) finishRegistration}
   * and {@link #finishAssertion(FinishAssertionOptions) finishAssertion} will accept responses
   * containing extension outputs for which there was no extension input.
   *
   * <p>The default is <code>false</code>.
   *
   * @see <a href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-extensions">§9. WebAuthn
   *     Extensions</a>
   */
  @Builder.Default private final boolean allowUnrequestedExtensions = false;

  /**
   * If <code>false</code>, {@link #finishRegistration(FinishRegistrationOptions)
   * finishRegistration} will only allow registrations where the attestation signature can be linked
   * to a trusted attestation root. This excludes self attestation and none attestation.
   *
   * <p>Regardless of the value of this option, invalid attestation statements of supported formats
   * will always be rejected. For example, a "packed" attestation statement with an invalid
   * signature will be rejected even if this option is set to <code>true</code>.
   *
   * <p>The default is <code>true</code>.
   */
  @Builder.Default private final boolean allowUntrustedAttestation = true;

  /**
   * If <code>true</code>, {@link #finishAssertion(FinishAssertionOptions) finishAssertion} will
   * succeed only if the {@link AuthenticatorData#getSignatureCounter() signature counter value} in
   * the response is strictly greater than the {@link RegisteredCredential#getSignatureCount()
   * stored signature counter value}, or if both counters are exactly zero.
   *
   * <p>The default is <code>true</code>.
   */
  @Builder.Default private final boolean validateSignatureCounter = true;

  private RelyingParty(
      @NonNull RelyingPartyIdentity identity,
      Set<String> origins,
      @NonNull CredentialRepository credentialRepository,
      @NonNull Optional<AppId> appId,
      @NonNull Optional<AttestationConveyancePreference> attestationConveyancePreference,
      @NonNull Optional<MetadataService> metadataService,
      List<PublicKeyCredentialParameters> preferredPubkeyParams,
      boolean allowOriginPort,
      boolean allowOriginSubdomain,
      boolean allowUnrequestedExtensions,
      boolean allowUntrustedAttestation,
      boolean validateSignatureCounter) {
    this.identity = identity;
    this.origins =
        origins != null
            ? CollectionUtil.immutableSet(origins)
            : Collections.singleton("https://" + identity.getId());

    for (String origin : this.origins) {
      try {
        new URL(origin);
      } catch (MalformedURLException e) {
        log.warn(
            "Allowed origin is not a valid URL, it will match only by exact string equality: {}",
            origin);
      }
    }

    this.credentialRepository = credentialRepository;
    this.appId = appId;
    this.attestationConveyancePreference = attestationConveyancePreference;
    this.metadataService = metadataService;
    this.preferredPubkeyParams = preferredPubkeyParams;
    this.allowOriginPort = allowOriginPort;
    this.allowOriginSubdomain = allowOriginSubdomain;
    this.allowUnrequestedExtensions = allowUnrequestedExtensions;
    this.allowUntrustedAttestation = allowUntrustedAttestation;
    this.validateSignatureCounter = validateSignatureCounter;
  }

  private static ByteArray generateChallenge() {
    byte[] bytes = new byte[32];
    random.nextBytes(bytes);
    return new ByteArray(bytes);
  }

  public PublicKeyCredentialCreationOptions startRegistration(
      StartRegistrationOptions startRegistrationOptions) {
    PublicKeyCredentialCreationOptionsBuilder builder =
        PublicKeyCredentialCreationOptions.builder()
            .rp(identity)
            .user(startRegistrationOptions.getUser())
            .challenge(generateChallenge())
            .pubKeyCredParams(preferredPubkeyParams)
            .excludeCredentials(
                credentialRepository.getCredentialIdsForUsername(
                    startRegistrationOptions.getUser().getName()))
            .authenticatorSelection(startRegistrationOptions.getAuthenticatorSelection())
            .extensions(
                startRegistrationOptions
                    .getExtensions()
                    .merge(
                        RegistrationExtensionInputs.builder()
                            .appidExclude(appId)
                            .credProps()
                            .build()))
            .timeout(startRegistrationOptions.getTimeout());
    attestationConveyancePreference.ifPresent(builder::attestation);
    return builder.build();
  }

  public RegistrationResult finishRegistration(FinishRegistrationOptions finishRegistrationOptions)
      throws RegistrationFailedException {
    try {
      return _finishRegistration(
              finishRegistrationOptions.getRequest(),
              finishRegistrationOptions.getResponse(),
              finishRegistrationOptions.getCallerTokenBindingId())
          .run();
    } catch (IllegalArgumentException e) {
      throw new RegistrationFailedException(e);
    }
  }

  /**
   * This method is NOT part of the public API.
   *
   * <p>This method is called internally by {@link #finishRegistration(FinishRegistrationOptions)}.
   * It is a separate method to facilitate testing; users should call {@link
   * #finishRegistration(FinishRegistrationOptions)} instead of this method.
   */
  FinishRegistrationSteps _finishRegistration(
      PublicKeyCredentialCreationOptions request,
      PublicKeyCredential<AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs>
          response,
      Optional<ByteArray> callerTokenBindingId) {
    return FinishRegistrationSteps.builder()
        .request(request)
        .response(response)
        .callerTokenBindingId(callerTokenBindingId)
        .credentialRepository(credentialRepository)
        .origins(origins)
        .rpId(identity.getId())
        .allowOriginPort(allowOriginPort)
        .allowOriginSubdomain(allowOriginSubdomain)
        .allowUnrequestedExtensions(allowUnrequestedExtensions)
        .allowUntrustedAttestation(allowUntrustedAttestation)
        .metadataService(metadataService)
        .build();
  }

  public AssertionRequest startAssertion(StartAssertionOptions startAssertionOptions) {
    PublicKeyCredentialRequestOptionsBuilder pkcro =
        PublicKeyCredentialRequestOptions.builder()
            .challenge(generateChallenge())
            .rpId(identity.getId())
            .allowCredentials(
                OptionalUtil.orElseOptional(
                        startAssertionOptions.getUsername(),
                        () ->
                            startAssertionOptions
                                .getUserHandle()
                                .flatMap(credentialRepository::getUsernameForUserHandle))
                    .map(
                        un ->
                            new ArrayList<>(credentialRepository.getCredentialIdsForUsername(un))))
            .extensions(
                startAssertionOptions
                    .getExtensions()
                    .merge(startAssertionOptions.getExtensions().toBuilder().appid(appId).build()))
            .timeout(startAssertionOptions.getTimeout());

    startAssertionOptions.getUserVerification().ifPresent(pkcro::userVerification);

    return AssertionRequest.builder()
        .publicKeyCredentialRequestOptions(pkcro.build())
        .username(startAssertionOptions.getUsername())
        .build();
  }

  /**
   * @throws InvalidSignatureCountException if {@link
   *     RelyingPartyBuilder#validateSignatureCounter(boolean) validateSignatureCounter} is <code>
   *     true</code>, the {@link AuthenticatorData#getSignatureCounter() signature count} in the
   *     response is less than or equal to the {@link RegisteredCredential#getSignatureCount()
   *     stored signature count}, and at least one of the signature count values is nonzero.
   * @throws AssertionFailedException if validation fails for any other reason.
   */
  public AssertionResult finishAssertion(FinishAssertionOptions finishAssertionOptions)
      throws AssertionFailedException {
    try {
      return _finishAssertion(
              finishAssertionOptions.getRequest(),
              finishAssertionOptions.getResponse(),
              finishAssertionOptions.getCallerTokenBindingId())
          .run();
    } catch (IllegalArgumentException e) {
      throw new AssertionFailedException(e);
    }
  }

  /**
   * This method is NOT part of the public API.
   *
   * <p>This method is called internally by {@link #finishAssertion(FinishAssertionOptions)}. It is
   * a separate method to facilitate testing; users should call {@link
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
        .allowOriginPort(allowOriginPort)
        .allowOriginSubdomain(allowOriginSubdomain)
        .allowUnrequestedExtensions(allowUnrequestedExtensions)
        .validateSignatureCounter(validateSignatureCounter)
        .build();
  }

  public static RelyingPartyBuilder.MandatoryStages builder() {
    return new RelyingPartyBuilder.MandatoryStages();
  }

  public static class RelyingPartyBuilder {
    private @NonNull Optional<AppId> appId = Optional.empty();
    private @NonNull Optional<AttestationConveyancePreference> attestationConveyancePreference =
        Optional.empty();
    private @NonNull Optional<MetadataService> metadataService = Optional.empty();

    public static class MandatoryStages {
      private final RelyingPartyBuilder builder = new RelyingPartyBuilder();

      /**
       * {@link RelyingPartyBuilder#identity(RelyingPartyIdentity) identity} is a required
       * parameter.
       *
       * @see RelyingPartyBuilder#identity(RelyingPartyIdentity)
       */
      public Step2 identity(RelyingPartyIdentity identity) {
        builder.identity(identity);
        return new Step2();
      }

      public class Step2 {
        /**
         * {@link RelyingPartyBuilder#credentialRepository(CredentialRepository)
         * credentialRepository} is a required parameter.
         *
         * @see RelyingPartyBuilder#credentialRepository(CredentialRepository)
         */
        public RelyingPartyBuilder credentialRepository(CredentialRepository credentialRepository) {
          return builder.credentialRepository(credentialRepository);
        }
      }
    }

    /**
     * The extension input to set for the <code>appid</code> and <code>appidExclude</code>
     * extensions.
     *
     * <p>You do not need this extension if you have not previously supported U2F. Its purpose is to
     * make already-registered U2F credentials forward-compatible with the WebAuthn API. It is not
     * needed for new registrations, even of U2F authenticators.
     *
     * <p>If this member is set, {@link #startAssertion(StartAssertionOptions) startAssertion} will
     * automatically set the <code>appid</code> extension input, and {@link
     * #finishAssertion(FinishAssertionOptions) finishAssertion} will adjust its verification logic
     * to also accept this AppID as an alternative to the RP ID. Likewise, {@link
     * #startRegistration(StartRegistrationOptions)} startRegistration} will automatically set the
     * <code>appidExclude</code> extension input.
     *
     * <p>By default, this is not set.
     *
     * @see AssertionExtensionInputs#getAppid()
     * @see RegistrationExtensionInputs#getAppidExclude()
     * @see <a
     *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-appid-extension">§10.1.
     *     FIDO AppID Extension (appid)</a>
     * @see <a
     *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-appid-exclude-extension">§10.2.
     *     FIDO AppID Exclusion Extension (appidExclude)</a>
     */
    public RelyingPartyBuilder appId(@NonNull Optional<AppId> appId) {
      this.appId = appId;
      return this;
    }

    /**
     * The extension input to set for the <code>appid</code> and <code>appidExclude</code>
     * extensions.
     *
     * <p>You do not need this extension if you have not previously supported U2F. Its purpose is to
     * make already-registered U2F credentials forward-compatible with the WebAuthn API. It is not
     * needed for new registrations, even of U2F authenticators.
     *
     * <p>If this member is set, {@link #startAssertion(StartAssertionOptions) startAssertion} will
     * automatically set the <code>appid</code> extension input, and {@link
     * #finishAssertion(FinishAssertionOptions) finishAssertion} will adjust its verification logic
     * to also accept this AppID as an alternative to the RP ID. Likewise, {@link
     * #startRegistration(StartRegistrationOptions)} startRegistration} will automatically set the
     * <code>appidExclude</code> extension input.
     *
     * <p>By default, this is not set.
     *
     * @see AssertionExtensionInputs#getAppid()
     * @see RegistrationExtensionInputs#getAppidExclude()
     * @see <a
     *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-appid-extension">§10.1.
     *     FIDO AppID Extension (appid)</a>
     * @see <a
     *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-appid-exclude-extension">§10.2.
     *     FIDO AppID Exclusion Extension (appidExclude)</a>
     */
    public RelyingPartyBuilder appId(@NonNull AppId appId) {
      return this.appId(Optional.of(appId));
    }

    /**
     * The argument for the {@link PublicKeyCredentialCreationOptions#getAttestation() attestation}
     * parameter in registration operations.
     *
     * <p>Unless your application has a concrete policy for authenticator attestation, it is
     * recommended to leave this parameter undefined.
     *
     * <p>If you set this, you may want to explicitly set {@link
     * RelyingPartyBuilder#allowUntrustedAttestation(boolean) allowUntrustedAttestation} and {@link
     * RelyingPartyBuilder#metadataService(MetadataService) metadataService} too.
     *
     * <p>By default, this is not set.
     *
     * @see PublicKeyCredentialCreationOptions#getAttestation()
     * @see <a href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-attestation">§6.4.
     *     Attestation</a>
     */
    public RelyingPartyBuilder attestationConveyancePreference(
        @NonNull Optional<AttestationConveyancePreference> attestationConveyancePreference) {
      this.attestationConveyancePreference = attestationConveyancePreference;
      return this;
    }

    /**
     * The argument for the {@link PublicKeyCredentialCreationOptions#getAttestation() attestation}
     * parameter in registration operations.
     *
     * <p>Unless your application has a concrete policy for authenticator attestation, it is
     * recommended to leave this parameter undefined.
     *
     * <p>If you set this, you may want to explicitly set {@link
     * RelyingPartyBuilder#allowUntrustedAttestation(boolean) allowUntrustedAttestation} and {@link
     * RelyingPartyBuilder#metadataService(MetadataService) metadataService} too.
     *
     * <p>By default, this is not set.
     *
     * @see PublicKeyCredentialCreationOptions#getAttestation()
     * @see <a href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-attestation">§6.4.
     *     Attestation</a>
     */
    public RelyingPartyBuilder attestationConveyancePreference(
        @NonNull AttestationConveyancePreference attestationConveyancePreference) {
      return this.attestationConveyancePreference(Optional.of(attestationConveyancePreference));
    }

    /**
     * A {@link MetadataService} instance to use for looking up device attestation metadata. This
     * matters only if {@link #getAttestationConveyancePreference()} is non-empty and not set to
     * {@link AttestationConveyancePreference#NONE}.
     *
     * <p>By default, this is not set.
     *
     * @see PublicKeyCredentialCreationOptions#getAttestation()
     * @see <a href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-attestation">§6.4.
     *     Attestation</a>
     */
    public RelyingPartyBuilder metadataService(@NonNull Optional<MetadataService> metadataService) {
      this.metadataService = metadataService;
      return this;
    }

    /**
     * A {@link MetadataService} instance to use for looking up device attestation metadata. This
     * matters only if {@link #getAttestationConveyancePreference()} is non-empty and not set to
     * {@link AttestationConveyancePreference#NONE}.
     *
     * <p>By default, this is not set.
     *
     * @see PublicKeyCredentialCreationOptions#getAttestation()
     * @see <a href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-attestation">§6.4.
     *     Attestation</a>
     */
    public RelyingPartyBuilder metadataService(@NonNull MetadataService metadataService) {
      return this.metadataService(Optional.of(metadataService));
    }
  }
}
