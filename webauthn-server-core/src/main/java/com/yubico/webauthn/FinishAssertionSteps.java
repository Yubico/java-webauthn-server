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

import static com.yubico.internal.util.ExceptionUtil.assertTrue;

import COSE.CoseException;
import com.yubico.internal.util.OptionalUtil;
import com.yubico.webauthn.data.AuthenticatorAssertionResponse;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.COSEAlgorithmIdentifier;
import com.yubico.webauthn.data.ClientAssertionExtensionOutputs;
import com.yubico.webauthn.data.CollectedClientData;
import com.yubico.webauthn.data.PublicKeyCredential;
import com.yubico.webauthn.data.UserVerificationRequirement;
import com.yubico.webauthn.exception.InvalidSignatureCountException;
import com.yubico.webauthn.extension.appid.AppId;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Optional;
import java.util.Set;
import lombok.AllArgsConstructor;
import lombok.Value;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@AllArgsConstructor
final class FinishAssertionSteps<C extends CredentialRecord> {

  private static final String CLIENT_DATA_TYPE = "webauthn.get";
  private static final String SPC_CLIENT_DATA_TYPE = "payment.get";

  private final AssertionRequest request;
  private final PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs>
      response;
  private final Optional<ByteArray> callerTokenBindingId;
  private final Set<String> origins;
  private final String rpId;
  private final Optional<CredentialRepository> credentialRepository;
  private final CredentialRepositoryV2<C> credentialRepositoryV2;
  private final Optional<UsernameRepository> usernameRepository;
  private final boolean allowOriginPort;
  private final boolean allowOriginSubdomain;
  private final boolean validateSignatureCounter;
  private final boolean isSecurePaymentConfirmation;

  static FinishAssertionSteps<RegisteredCredential> fromV1(
      RelyingParty rp, FinishAssertionOptions options) {
    final CredentialRepository credRepo = rp.getCredentialRepository();
    final CredentialRepositoryV1ToV2Adapter credRepoV2 =
        new CredentialRepositoryV1ToV2Adapter(credRepo);
    return new FinishAssertionSteps<>(
        options.getRequest(),
        options.getResponse(),
        options.getCallerTokenBindingId(),
        rp.getOrigins(),
        rp.getIdentity().getId(),
        Optional.of(credRepo),
        credRepoV2,
        Optional.of(credRepoV2),
        rp.isAllowOriginPort(),
        rp.isAllowOriginSubdomain(),
        rp.isValidateSignatureCounter(),
        options.isSecurePaymentConfirmation());
  }

  FinishAssertionSteps(RelyingPartyV2<C> rp, FinishAssertionOptions options) {
    this(
        options.getRequest(),
        options.getResponse(),
        options.getCallerTokenBindingId(),
        rp.getOrigins(),
        rp.getIdentity().getId(),
        Optional.empty(),
        rp.getCredentialRepository(),
        Optional.ofNullable(rp.getUsernameRepository()),
        rp.isAllowOriginPort(),
        rp.isAllowOriginSubdomain(),
        rp.isValidateSignatureCounter(),
        options.isSecurePaymentConfirmation());
  }

  private Optional<String> getUsernameForUserHandle(final ByteArray userHandle) {
    return credentialRepository.flatMap(credRepo -> credRepo.getUsernameForUserHandle(userHandle));
  }

  public Step5 begin() {
    return new Step5();
  }

  public AssertionResult run() throws InvalidSignatureCountException {
    return begin().run();
  }

  public AssertionResultV2<C> runV2() throws InvalidSignatureCountException {
    return begin().runV2();
  }

  interface Step<C extends CredentialRecord, Next extends Step<C, ?>> {
    Next nextStep();

    void validate() throws InvalidSignatureCountException;

    default Optional<AssertionResult> result() {
      return Optional.empty();
    }

    default Optional<AssertionResultV2<C>> resultV2() {
      return Optional.empty();
    }

    default Next next() throws InvalidSignatureCountException {
      validate();
      return nextStep();
    }

    default AssertionResult run() throws InvalidSignatureCountException {
      if (result().isPresent()) {
        return result().get();
      } else {
        return next().run();
      }
    }

    default AssertionResultV2<C> runV2() throws InvalidSignatureCountException {
      if (resultV2().isPresent()) {
        return resultV2().get();
      } else {
        return next().runV2();
      }
    }
  }

  // Steps 1 through 4 are to create the request and run the client-side part

  @Value
  class Step5 implements Step<C, Step6> {
    @Override
    public Step6 nextStep() {
      return new Step6();
    }

    @Override
    public void validate() {
      request
          .getPublicKeyCredentialRequestOptions()
          .getAllowCredentials()
          .filter(allowCredentials -> !allowCredentials.isEmpty())
          .ifPresent(
              allowed -> {
                assertTrue(
                    allowed.stream().anyMatch(allow -> allow.getId().equals(response.getId())),
                    "Unrequested credential ID: %s",
                    response.getId());
              });
    }
  }

  @Value
  class Step6 implements Step<C, Step7> {

    private final Optional<ByteArray> requestedUserHandle;
    private final Optional<String> requestedUsername;
    private final Optional<ByteArray> responseUserHandle;

    private final Optional<ByteArray> effectiveRequestUserHandle;
    private final Optional<String> effectiveRequestUsername;
    private final boolean userHandleDerivedFromUsername;

    private final Optional<ByteArray> finalUserHandle;
    private final Optional<String> finalUsername;
    private final Optional<C> registration;

    public Step6() {
      requestedUserHandle = request.getUserHandle();
      requestedUsername = request.getUsername();
      responseUserHandle = response.getResponse().getUserHandle();

      effectiveRequestUserHandle =
          OptionalUtil.orElseOptional(
              requestedUserHandle,
              () ->
                  usernameRepository.flatMap(
                      unr -> requestedUsername.flatMap(unr::getUserHandleForUsername)));

      effectiveRequestUsername =
          OptionalUtil.orElseOptional(
              requestedUsername,
              () ->
                  requestedUserHandle.flatMap(FinishAssertionSteps.this::getUsernameForUserHandle));

      userHandleDerivedFromUsername =
          !requestedUserHandle.isPresent() && effectiveRequestUserHandle.isPresent();

      finalUserHandle = OptionalUtil.orOptional(effectiveRequestUserHandle, responseUserHandle);
      finalUsername =
          OptionalUtil.orElseOptional(
              effectiveRequestUsername,
              () -> finalUserHandle.flatMap(FinishAssertionSteps.this::getUsernameForUserHandle));

      registration =
          finalUserHandle.flatMap(uh -> credentialRepositoryV2.lookup(response.getId(), uh));
    }

    @Override
    public Step7 nextStep() {
      return new Step7(finalUsername, finalUserHandle.get(), registration);
    }

    @Override
    public void validate() {
      assertTrue(
          finalUserHandle.isPresent(),
          "Could not identify user to authenticate: none of requested username, requested user handle or response user handle are set.");

      if (requestedUserHandle.isPresent() && responseUserHandle.isPresent()) {
        assertTrue(
            requestedUserHandle.get().equals(responseUserHandle.get()),
            "User handle set in request (%s) does not match user handle in response (%s).",
            requestedUserHandle.get(),
            responseUserHandle.get());
      }

      if (userHandleDerivedFromUsername && responseUserHandle.isPresent()) {
        assertTrue(
            effectiveRequestUserHandle.get().equals(responseUserHandle.get()),
            "User handle in request (%s) (derived from username: %s) does not match user handle in response (%s).",
            effectiveRequestUserHandle.get(),
            requestedUsername.get(),
            responseUserHandle.get());
      }

      assertTrue(registration.isPresent(), "Unknown credential: %s", response.getId());

      assertTrue(
          finalUserHandle.get().equals(registration.get().getUserHandle()),
          "User handle %s does not own credential %s",
          finalUserHandle.get(),
          response.getId());

      if (credentialRepository.isPresent()) {
        assertTrue(
            finalUsername.isPresent(),
            "Unknown username for user handle: %s",
            finalUserHandle.get());
      }
    }
  }

  @Value
  class Step7 implements Step<C, Step8> {
    private final Optional<String> username;
    private final ByteArray userHandle;
    private final Optional<C> credential;

    @Override
    public Step8 nextStep() {
      return new Step8(username, credential.get());
    }

    @Override
    public void validate() {
      assertTrue(
          credential.isPresent(),
          "Unknown credential. Credential ID: %s, user handle: %s",
          response.getId(),
          userHandle);
    }
  }

  @Value
  class Step8 implements Step<C, Step10> {

    private final Optional<String> username;
    private final C credential;

    @Override
    public void validate() {
      assertTrue(clientData() != null, "Missing client data.");
      assertTrue(authenticatorData() != null, "Missing authenticator data.");
      assertTrue(signature() != null, "Missing signature.");
    }

    @Override
    public Step10 nextStep() {
      return new Step10(username, credential);
    }

    public ByteArray authenticatorData() {
      return response.getResponse().getAuthenticatorData();
    }

    public ByteArray clientData() {
      return response.getResponse().getClientDataJSON();
    }

    public ByteArray signature() {
      return response.getResponse().getSignature();
    }
  }

  // Nothing to do for step 9

  @Value
  class Step10 implements Step<C, Step11> {
    private final Optional<String> username;
    private final C credential;

    @Override
    public void validate() {
      assertTrue(clientData() != null, "Missing client data.");
    }

    @Override
    public Step11 nextStep() {
      return new Step11(username, credential, clientData());
    }

    public CollectedClientData clientData() {
      return response.getResponse().getClientData();
    }
  }

  @Value
  class Step11 implements Step<C, Step12> {
    private final Optional<String> username;
    private final C credential;
    private final CollectedClientData clientData;

    @Override
    public void validate() {
      final String expectedType =
          isSecurePaymentConfirmation ? SPC_CLIENT_DATA_TYPE : CLIENT_DATA_TYPE;
      assertTrue(
          expectedType.equals(clientData.getType()),
          "The \"type\" in the client data must be exactly \"%s\", was: %s",
          expectedType,
          clientData.getType());
    }

    @Override
    public Step12 nextStep() {
      return new Step12(username, credential);
    }
  }

  @Value
  class Step12 implements Step<C, Step13> {
    private final Optional<String> username;
    private final C credential;

    @Override
    public void validate() {
      assertTrue(
          request
              .getPublicKeyCredentialRequestOptions()
              .getChallenge()
              .equals(response.getResponse().getClientData().getChallenge()),
          "Incorrect challenge.");
    }

    @Override
    public Step13 nextStep() {
      return new Step13(username, credential);
    }
  }

  @Value
  class Step13 implements Step<C, Step14> {
    private final Optional<String> username;
    private final C credential;

    @Override
    public void validate() {
      final String responseOrigin = response.getResponse().getClientData().getOrigin();
      assertTrue(
          OriginMatcher.isAllowed(responseOrigin, origins, allowOriginPort, allowOriginSubdomain),
          "Incorrect origin: " + responseOrigin);
    }

    @Override
    public Step14 nextStep() {
      return new Step14(username, credential);
    }
  }

  @Value
  class Step14 implements Step<C, Step15> {
    private final Optional<String> username;
    private final C credential;

    @Override
    public void validate() {
      TokenBindingValidator.validate(
          response.getResponse().getClientData().getTokenBinding(), callerTokenBindingId);
    }

    @Override
    public Step15 nextStep() {
      return new Step15(username, credential);
    }
  }

  @Value
  class Step15 implements Step<C, Step16> {
    private final Optional<String> username;
    private final C credential;

    @Override
    public void validate() {
      try {
        assertTrue(
            Crypto.sha256(rpId)
                .equals(response.getResponse().getParsedAuthenticatorData().getRpIdHash()),
            "Wrong RP ID hash.");
      } catch (IllegalArgumentException e) {
        Optional<AppId> appid =
            request.getPublicKeyCredentialRequestOptions().getExtensions().getAppid();
        if (appid.isPresent()) {
          assertTrue(
              Crypto.sha256(appid.get().getId())
                  .equals(response.getResponse().getParsedAuthenticatorData().getRpIdHash()),
              "Wrong RP ID hash.");
        } else {
          throw e;
        }
      }
    }

    @Override
    public Step16 nextStep() {
      return new Step16(username, credential);
    }
  }

  @Value
  class Step16 implements Step<C, Step17> {
    private final Optional<String> username;
    private final C credential;

    @Override
    public void validate() {
      assertTrue(
          response.getResponse().getParsedAuthenticatorData().getFlags().UP,
          "User Presence is required.");
    }

    @Override
    public Step17 nextStep() {
      return new Step17(username, credential);
    }
  }

  @Value
  class Step17 implements Step<C, PendingStep16> {
    private final Optional<String> username;
    private final C credential;

    @Override
    public void validate() {
      if (request
          .getPublicKeyCredentialRequestOptions()
          .getUserVerification()
          .equals(Optional.of(UserVerificationRequirement.REQUIRED))) {
        assertTrue(
            response.getResponse().getParsedAuthenticatorData().getFlags().UV,
            "User Verification is required.");
      }
    }

    @Override
    public PendingStep16 nextStep() {
      return new PendingStep16(username, credential);
    }
  }

  @Value
  // Step 16 in editor's draft as of 2022-11-09 https://w3c.github.io/webauthn/
  // TODO: Finalize this when spec matures
  class PendingStep16 implements Step<C, Step18> {
    private final Optional<String> username;
    private final C credential;

    @Override
    public void validate() {
      assertTrue(
          !credential.isBackupEligible().isPresent()
              || response.getResponse().getParsedAuthenticatorData().getFlags().BE
                  == credential.isBackupEligible().get(),
          "Backup eligibility must not change; Stored: BE=%s, received: BE=%s for credential: %s",
          credential.isBackupEligible(),
          response.getResponse().getParsedAuthenticatorData().getFlags().BE,
          credential.getCredentialId());
    }

    @Override
    public Step18 nextStep() {
      return new Step18(username, credential);
    }
  }

  @Value
  class Step18 implements Step<C, Step19> {
    private final Optional<String> username;
    private final C credential;

    @Override
    public void validate() {}

    @Override
    public Step19 nextStep() {
      return new Step19(username, credential);
    }
  }

  @Value
  class Step19 implements Step<C, Step20> {
    private final Optional<String> username;
    private final C credential;

    @Override
    public void validate() {
      assertTrue(clientDataJsonHash().size() == 32, "Failed to compute hash of client data");
    }

    @Override
    public Step20 nextStep() {
      return new Step20(username, credential, clientDataJsonHash());
    }

    public ByteArray clientDataJsonHash() {
      return Crypto.sha256(response.getResponse().getClientDataJSON());
    }
  }

  @Value
  class Step20 implements Step<C, Step21> {
    private final Optional<String> username;
    private final C credential;
    private final ByteArray clientDataJsonHash;

    @Override
    public void validate() {
      final ByteArray cose = credential.getPublicKeyCose();
      final PublicKey key;

      try {
        key = WebAuthnCodecs.importCosePublicKey(cose);
      } catch (CoseException | IOException | InvalidKeySpecException e) {
        throw new IllegalArgumentException(
            String.format(
                "Failed to decode public key: Credential ID: %s COSE: %s",
                credential.getCredentialId().getBase64Url(), cose.getBase64Url()),
            e);
      } catch (NoSuchAlgorithmException e) {
        throw new RuntimeException(e);
      }

      final COSEAlgorithmIdentifier alg =
          COSEAlgorithmIdentifier.fromPublicKey(cose)
              .orElseThrow(
                  () ->
                      new IllegalArgumentException(
                          String.format("Failed to decode \"alg\" from COSE key: %s", cose)));

      if (!Crypto.verifySignature(key, signedBytes(), response.getResponse().getSignature(), alg)) {
        throw new IllegalArgumentException("Invalid assertion signature.");
      }
    }

    @Override
    public Step21 nextStep() {
      return new Step21(username, credential);
    }

    public ByteArray signedBytes() {
      return response.getResponse().getAuthenticatorData().concat(clientDataJsonHash);
    }
  }

  @Value
  class Step21 implements Step<C, Finished> {
    private final Optional<String> username;
    private final C credential;
    private final long assertionSignatureCount;
    private final long storedSignatureCountBefore;

    public Step21(Optional<String> username, C credential) {
      this.username = username;
      this.credential = credential;
      this.assertionSignatureCount =
          response.getResponse().getParsedAuthenticatorData().getSignatureCounter();
      this.storedSignatureCountBefore = credential.getSignatureCount();
    }

    @Override
    public void validate() throws InvalidSignatureCountException {
      if (validateSignatureCounter && !signatureCounterValid()) {
        throw new InvalidSignatureCountException(
            response.getId(), storedSignatureCountBefore + 1, assertionSignatureCount);
      }
    }

    private boolean signatureCounterValid() {
      return (assertionSignatureCount == 0 && storedSignatureCountBefore == 0)
          || assertionSignatureCount > storedSignatureCountBefore;
    }

    @Override
    public Finished nextStep() {
      return new Finished(credential, username, assertionSignatureCount, signatureCounterValid());
    }
  }

  @Value
  class Finished implements Step<C, Finished> {
    private final C credential;
    private final Optional<String> username;
    private final long assertionSignatureCount;
    private final boolean signatureCounterValid;

    @Override
    public void validate() {
      /* No-op */
    }

    @Override
    public Finished nextStep() {
      return this;
    }

    @Override
    public Optional<AssertionResult> result() {
      return Optional.of(
          new AssertionResult(
              true,
              response,
              (RegisteredCredential) credential,
              username.get(),
              signatureCounterValid));
    }

    public Optional<AssertionResultV2<C>> resultV2() {
      return Optional.of(
          new AssertionResultV2<C>(true, response, credential, signatureCounterValid));
    }
  }
}
