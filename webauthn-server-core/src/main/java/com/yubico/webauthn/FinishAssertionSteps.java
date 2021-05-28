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

import static com.yubico.internal.util.ExceptionUtil.assure;

import COSE.CoseException;
import com.yubico.internal.util.CollectionUtil;
import com.yubico.webauthn.data.AuthenticatorAssertionExtensionOutputs;
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
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import lombok.Builder;
import lombok.Value;
import lombok.extern.slf4j.Slf4j;

@Builder
@Slf4j
final class FinishAssertionSteps {

  private static final String CLIENT_DATA_TYPE = "webauthn.get";

  private final AssertionRequest request;
  private final PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs>
      response;
  private final Optional<ByteArray> callerTokenBindingId;
  private final Set<String> origins;
  private final String rpId;
  private final CredentialRepository credentialRepository;

  @Builder.Default private final boolean allowOriginPort = false;
  @Builder.Default private final boolean allowOriginSubdomain = false;
  @Builder.Default private final boolean allowUnrequestedExtensions = false;
  @Builder.Default private final boolean validateSignatureCounter = true;

  public Step0 begin() {
    return new Step0();
  }

  public AssertionResult run() throws InvalidSignatureCountException {
    return begin().run();
  }

  interface Step<Next extends Step<?>> {
    Next nextStep();

    void validate() throws InvalidSignatureCountException;

    List<String> getPrevWarnings();

    default Optional<AssertionResult> result() {
      return Optional.empty();
    }

    default List<String> getWarnings() {
      return Collections.emptyList();
    }

    default List<String> allWarnings() {
      List<String> result = new ArrayList<>(getPrevWarnings().size() + getWarnings().size());
      result.addAll(getPrevWarnings());
      result.addAll(getWarnings());
      return CollectionUtil.immutableList(result);
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
  }

  @Value
  class Step0 implements Step<Step1> {
    @Override
    public Step1 nextStep() {
      return new Step1(username().get(), userHandle().get(), allWarnings());
    }

    @Override
    public void validate() {
      assure(
          request.getUsername().isPresent() || response.getResponse().getUserHandle().isPresent(),
          "At least one of username and user handle must be given; none was.");
      assure(
          userHandle().isPresent(),
          "No user found for username: %s, userHandle: %s",
          request.getUsername(),
          response.getResponse().getUserHandle());
      assure(
          username().isPresent(),
          "No user found for username: %s, userHandle: %s",
          request.getUsername(),
          response.getResponse().getUserHandle());
    }

    @Override
    public List<String> getPrevWarnings() {
      return Collections.emptyList();
    }

    private Optional<ByteArray> userHandle() {
      return response
          .getResponse()
          .getUserHandle()
          .map(Optional::of)
          .orElseGet(
              () -> credentialRepository.getUserHandleForUsername(request.getUsername().get()));
    }

    private Optional<String> username() {
      return request
          .getUsername()
          .map(Optional::of)
          .orElseGet(
              () ->
                  credentialRepository.getUsernameForUserHandle(
                      response.getResponse().getUserHandle().get()));
    }
  }

  @Value
  class Step1 implements Step<Step2> {
    private final String username;
    private final ByteArray userHandle;
    private final List<String> prevWarnings;

    @Override
    public Step2 nextStep() {
      return new Step2(username, userHandle, allWarnings());
    }

    @Override
    public void validate() {
      request
          .getPublicKeyCredentialRequestOptions()
          .getAllowCredentials()
          .ifPresent(
              allowed -> {
                assure(
                    allowed.stream().anyMatch(allow -> allow.getId().equals(response.getId())),
                    "Unrequested credential ID: %s",
                    response.getId());
              });
    }
  }

  @Value
  class Step2 implements Step<Step3> {
    private final String username;
    private final ByteArray userHandle;
    private final List<String> prevWarnings;

    @Override
    public Step3 nextStep() {
      return new Step3(username, userHandle, allWarnings());
    }

    @Override
    public void validate() {
      Optional<RegisteredCredential> registration =
          credentialRepository.lookup(response.getId(), userHandle);

      assure(registration.isPresent(), "Unknown credential: %s", response.getId());

      assure(
          userHandle.equals(registration.get().getUserHandle()),
          "User handle %s does not own credential %s",
          userHandle,
          response.getId());
    }
  }

  @Value
  class Step3 implements Step<Step4> {
    private final String username;
    private final ByteArray userHandle;
    private final List<String> prevWarnings;

    @Override
    public Step4 nextStep() {
      return new Step4(username, userHandle, credential(), allWarnings());
    }

    @Override
    public void validate() {
      assure(
          maybeCredential().isPresent(),
          "Unknown credential. Credential ID: %s, user handle: %s",
          response.getId(),
          userHandle);
    }

    private Optional<RegisteredCredential> maybeCredential() {
      return credentialRepository.lookup(response.getId(), userHandle);
    }

    public RegisteredCredential credential() {
      return maybeCredential().get();
    }
  }

  @Value
  class Step4 implements Step<Step5> {

    private final String username;
    private final ByteArray userHandle;
    private final RegisteredCredential credential;
    private final List<String> prevWarnings;

    @Override
    public void validate() {
      assure(clientData() != null, "Missing client data.");
      assure(authenticatorData() != null, "Missing authenticator data.");
      assure(signature() != null, "Missing signature.");
    }

    @Override
    public Step5 nextStep() {
      return new Step5(username, userHandle, credential, allWarnings());
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

  @Value
  class Step5 implements Step<Step6> {
    private final String username;
    private final ByteArray userHandle;
    private final RegisteredCredential credential;
    private final List<String> prevWarnings;

    // Nothing to do
    @Override
    public void validate() {}

    @Override
    public Step6 nextStep() {
      return new Step6(username, userHandle, credential, allWarnings());
    }
  }

  @Value
  class Step6 implements Step<Step7> {
    private final String username;
    private final ByteArray userHandle;
    private final RegisteredCredential credential;
    private final List<String> prevWarnings;

    @Override
    public void validate() {
      assure(clientData() != null, "Missing client data.");
    }

    @Override
    public Step7 nextStep() {
      return new Step7(username, userHandle, credential, clientData(), allWarnings());
    }

    public CollectedClientData clientData() {
      return response.getResponse().getClientData();
    }
  }

  @Value
  class Step7 implements Step<Step8> {

    private final String username;
    private final ByteArray userHandle;
    private final RegisteredCredential credential;
    private final CollectedClientData clientData;
    private final List<String> prevWarnings;

    private List<String> warnings = new LinkedList<>();

    @Override
    public List<String> getWarnings() {
      return CollectionUtil.immutableList(warnings);
    }

    @Override
    public void validate() {
      assure(
          CLIENT_DATA_TYPE.equals(clientData.getType()),
          "The \"type\" in the client data must be exactly \"%s\", was: %s",
          CLIENT_DATA_TYPE,
          clientData.getType());
    }

    @Override
    public Step8 nextStep() {
      return new Step8(username, userHandle, credential, allWarnings());
    }
  }

  @Value
  class Step8 implements Step<Step9> {
    private final String username;
    private final ByteArray userHandle;
    private final RegisteredCredential credential;
    private final List<String> prevWarnings;

    @Override
    public void validate() {
      assure(
          request
              .getPublicKeyCredentialRequestOptions()
              .getChallenge()
              .equals(response.getResponse().getClientData().getChallenge()),
          "Incorrect challenge.");
    }

    @Override
    public Step9 nextStep() {
      return new Step9(username, userHandle, credential, allWarnings());
    }
  }

  @Value
  class Step9 implements Step<Step10> {
    private final String username;
    private final ByteArray userHandle;
    private final RegisteredCredential credential;
    private final List<String> prevWarnings;

    @Override
    public void validate() {
      final String responseOrigin = response.getResponse().getClientData().getOrigin();
      assure(
          OriginMatcher.isAllowed(responseOrigin, origins, allowOriginPort, allowOriginSubdomain),
          "Incorrect origin: " + responseOrigin);
    }

    @Override
    public Step10 nextStep() {
      return new Step10(username, userHandle, credential, allWarnings());
    }
  }

  @Value
  class Step10 implements Step<Step11> {
    private final String username;
    private final ByteArray userHandle;
    private final RegisteredCredential credential;
    private final List<String> prevWarnings;

    @Override
    public void validate() {
      TokenBindingValidator.validate(
          response.getResponse().getClientData().getTokenBinding(), callerTokenBindingId);
    }

    @Override
    public Step11 nextStep() {
      return new Step11(username, userHandle, credential, allWarnings());
    }
  }

  @Value
  class Step11 implements Step<Step12> {
    private final String username;
    private final ByteArray userHandle;
    private final RegisteredCredential credential;
    private final List<String> prevWarnings;

    @Override
    public void validate() {
      try {
        assure(
            Crypto.sha256(rpId)
                .equals(response.getResponse().getParsedAuthenticatorData().getRpIdHash()),
            "Wrong RP ID hash.");
      } catch (IllegalArgumentException e) {
        Optional<AppId> appid =
            request.getPublicKeyCredentialRequestOptions().getExtensions().getAppid();
        if (appid.isPresent()) {
          assure(
              Crypto.sha256(appid.get().getId())
                  .equals(response.getResponse().getParsedAuthenticatorData().getRpIdHash()),
              "Wrong RP ID hash.");
        } else {
          throw e;
        }
      }
    }

    @Override
    public Step12 nextStep() {
      return new Step12(username, userHandle, credential, allWarnings());
    }
  }

  @Value
  class Step12 implements Step<Step13> {
    private final String username;
    private final ByteArray userHandle;
    private final RegisteredCredential credential;
    private final List<String> prevWarnings;

    @Override
    public void validate() {
      assure(
          response.getResponse().getParsedAuthenticatorData().getFlags().UP,
          "User Presence is required.");
    }

    @Override
    public Step13 nextStep() {
      return new Step13(username, userHandle, credential, allWarnings());
    }
  }

  @Value
  class Step13 implements Step<Step14> {
    private final String username;
    private final ByteArray userHandle;
    private final RegisteredCredential credential;
    private final List<String> prevWarnings;

    @Override
    public void validate() {
      if (request.getPublicKeyCredentialRequestOptions().getUserVerification()
          == UserVerificationRequirement.REQUIRED) {
        assure(
            response.getResponse().getParsedAuthenticatorData().getFlags().UV,
            "User Verification is required.");
      }
    }

    @Override
    public Step14 nextStep() {
      return new Step14(username, userHandle, credential, allWarnings());
    }
  }

  @Value
  class Step14 implements Step<Step15> {
    private final String username;
    private final ByteArray userHandle;
    private final RegisteredCredential credential;
    private final List<String> prevWarnings;

    @Override
    public void validate() {
      if (!allowUnrequestedExtensions) {
        ExtensionsValidation.validate(
            request.getPublicKeyCredentialRequestOptions().getExtensions(), response);
      }
    }

    @Override
    public List<String> getWarnings() {
      try {
        ExtensionsValidation.validate(
            request.getPublicKeyCredentialRequestOptions().getExtensions(), response);
        return Collections.emptyList();
      } catch (Exception e) {
        return CollectionUtil.immutableList(Collections.singletonList(e.getMessage()));
      }
    }

    @Override
    public Step15 nextStep() {
      return new Step15(username, userHandle, credential, allWarnings());
    }
  }

  @Value
  class Step15 implements Step<Step16> {
    private final String username;
    private final ByteArray userHandle;
    private final RegisteredCredential credential;
    private final List<String> prevWarnings;

    @Override
    public void validate() {
      assure(clientDataJsonHash().size() == 32, "Failed to compute hash of client data");
    }

    @Override
    public Step16 nextStep() {
      return new Step16(username, userHandle, credential, clientDataJsonHash(), allWarnings());
    }

    public ByteArray clientDataJsonHash() {
      return Crypto.sha256(response.getResponse().getClientDataJSON());
    }
  }

  @Value
  class Step16 implements Step<Step17> {
    private final String username;
    private final ByteArray userHandle;
    private final RegisteredCredential credential;
    private final ByteArray clientDataJsonHash;
    private final List<String> prevWarnings;

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
          WebAuthnCodecs.getCoseKeyAlg(cose)
              .orElseThrow(
                  () ->
                      new IllegalArgumentException(
                          String.format("Failed to decode \"alg\" from COSE key: %s", cose)));

      if (!Crypto.verifySignature(key, signedBytes(), response.getResponse().getSignature(), alg)) {
        throw new IllegalArgumentException("Invalid assertion signature.");
      }
    }

    @Override
    public Step17 nextStep() {
      return new Step17(username, userHandle, allWarnings());
    }

    public ByteArray signedBytes() {
      return response.getResponse().getAuthenticatorData().concat(clientDataJsonHash);
    }
  }

  @Value
  class Step17 implements Step<Finished> {
    private final String username;
    private final ByteArray userHandle;
    private final List<String> prevWarnings;

    @Override
    public void validate() throws InvalidSignatureCountException {
      if (validateSignatureCounter && !signatureCounterValid()) {
        throw new InvalidSignatureCountException(
            response.getId(), storedSignatureCountBefore() + 1, assertionSignatureCount());
      }
    }

    private boolean signatureCounterValid() {
      return (assertionSignatureCount() == 0 && storedSignatureCountBefore() == 0)
          || assertionSignatureCount() > storedSignatureCountBefore();
    }

    @Override
    public Finished nextStep() {
      return new Finished(
          username, userHandle, assertionSignatureCount(), signatureCounterValid(), allWarnings());
    }

    private long storedSignatureCountBefore() {
      return credentialRepository
          .lookup(response.getId(), userHandle)
          .map(RegisteredCredential::getSignatureCount)
          .orElse(0L);
    }

    private long assertionSignatureCount() {
      return response.getResponse().getParsedAuthenticatorData().getSignatureCounter();
    }
  }

  @Value
  class Finished implements Step<Finished> {
    private final String username;
    private final ByteArray userHandle;
    private final long assertionSignatureCount;
    private final boolean signatureCounterValid;
    private final List<String> prevWarnings;

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
          AssertionResult.builder()
              .success(true)
              .credentialId(response.getId())
              .userHandle(userHandle)
              .username(username)
              .signatureCount(assertionSignatureCount)
              .signatureCounterValid(signatureCounterValid)
              .clientExtensionOutputs(response.getClientExtensionResults())
              .assertionExtensionOutputs(
                  AuthenticatorAssertionExtensionOutputs.fromAuthenticatorData(
                          response.getResponse().getParsedAuthenticatorData())
                      .orElse(null))
              .warnings(allWarnings())
              .build());
    }
  }
}
