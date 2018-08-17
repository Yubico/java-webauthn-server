package com.yubico.webauthn;


import com.yubico.u2f.crypto.Crypto;
import com.yubico.u2f.data.messages.key.util.U2fB64Encoding;
import com.yubico.u2f.exceptions.U2fBadInputException;
import com.yubico.util.ExceptionUtil;
import com.yubico.webauthn.data.AssertionRequest;
import com.yubico.webauthn.data.AssertionResult;
import com.yubico.webauthn.data.AuthenticatorAssertionResponse;
import com.yubico.webauthn.data.CollectedClientData;
import com.yubico.webauthn.data.PublicKeyCredential;
import com.yubico.webauthn.data.RegisteredCredential;
import com.yubico.webauthn.data.UserVerificationRequirement;
import com.yubico.webauthn.impl.ExtensionsValidation;
import com.yubico.webauthn.impl.TokenBindingValidator;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import lombok.Builder;
import lombok.Getter;
import lombok.Value;
import lombok.extern.slf4j.Slf4j;


@Builder
@Slf4j
public class FinishAssertionSteps {

    private static final String CLIENT_DATA_TYPE = "webauthn.get";

    private final AssertionRequest request;
    private final PublicKeyCredential<AuthenticatorAssertionResponse> response;
    private final Optional<String> callerTokenBindingId;
    private final List<String> origins;
    private final String rpId;
    private final Crypto crypto;
    private final CredentialRepository credentialRepository;

    @Builder.Default
    private final boolean allowMissingTokenBinding = false;
    @Builder.Default
    private final boolean validateTypeAttribute = true;
    @Builder.Default
    private final boolean validateSignatureCounter = true;
    @Builder.Default
    private final boolean allowUnrequestedExtensions = false;

  private interface Step<A extends Step<?, ?>, B extends Step<?, ?>> {
      B nextStep();
      void validate();
      List<String> getPrevWarnings();

    default boolean isFinished() { return false; }

    default Optional<AssertionResult> result() { return Optional.empty(); }

    default List<String> getWarnings() { return Collections.emptyList(); }

    default List<String> allWarnings() {
          List<String> result = new ArrayList<>(getPrevWarnings().size() + getWarnings().size());
          result.addAll(getPrevWarnings());
          result.addAll(getWarnings());
          return Collections.unmodifiableList(result);
    }

    default B next() {
        validate();
        return nextStep();
    }

    default AssertionResult run() {
        if (isFinished()) {
            return result().get();
        } else {
            return next().run();
        }
    }
  }

  public Step0 begin() { return new Step0(); }

  public AssertionResult run() { return begin().run(); }

  @Value
  public class Step0 implements Step<Step0, Step1> {
    @Override
    public Step1 nextStep() {
        return new Step1(username().get(), userHandle().get(), allWarnings());
    }

    @Override
    public void validate() {
      if (!(
        request.getUsername().isPresent() || response.getResponse().getUserHandle().isPresent()
        )) {
          throw new IllegalArgumentException("At least one of username and user handle must be given; none was.");
      }
      if (!userHandle().isPresent()) {
          throw new IllegalArgumentException(String.format(
              "No user found for username: %s, userHandle: %s",
              request.getUsername(), response.getResponse().getUserHandleBase64()
          ));
      }
      if (!username().isPresent()) {
          throw new IllegalArgumentException(String.format(
            "No user found for username: %s, userHandle: %s",
          request.getUsername(), response.getResponse().getUserHandleBase64()
          ));
      }
    }

    @Override
    public List<String> getPrevWarnings() {
        return Collections.emptyList();
    }

    private Optional<String> userHandle() {
        return Optional.ofNullable(response.getResponse().getUserHandleBase64())
            .map(Optional::of)
            .orElseGet(() -> credentialRepository.getUserHandleForUsername(request.getUsername().get()));
    }

    private Optional<String> username() {
        return request.getUsername()
            .map(Optional::of)
            .orElseGet(() -> credentialRepository.getUsernameForUserHandle(response.getResponse().getUserHandleBase64()));
    }
  }

  @Value
  public class Step1 implements Step<Step0, Step2> {
      private final String username;
      private final String userHandle;
      private final List<String> prevWarnings;

    @Override
    public Step2 nextStep() {
        return new Step2(username, userHandle, allWarnings());
    }

    @Override
    public void validate(){
      request.getPublicKeyCredentialRequestOptions().getAllowCredentials().ifPresent(allowed -> {
          if (!(
              allowed.stream().anyMatch(allow -> Arrays.equals(allow.getId(), response.getRawId()))
              )) {
              throw new IllegalArgumentException("Unrequested credential ID: " + response.getId());
          }
      });
    }
  }

  @Value
  public class Step2 implements Step<Step1, Step3> {
      private final String username;
      private final String userHandle;
    private final List<String> prevWarnings;

    @Override
    public Step3 nextStep() {
        return new Step3(username, userHandle, allWarnings());
    }

    @Override
    public void validate() {
      Optional<RegisteredCredential> registration = credentialRepository.lookup(response.getId(), userHandle);

        if (!registration.isPresent()) {
           throw new IllegalArgumentException(String.format("Unknown credential: " + response.getId()) );
        }

      if (!Objects.equals(registration.get().getUserHandleBase64(), userHandle)) {
          throw new IllegalArgumentException(String.format(
              "User handle ${userHandle} does not own credential ${response.getId}", userHandle, response.getId()));
      }
    }
  }

  @Value
  public class Step3 implements Step<Step2, Step4> {
      private final String username;
        private final String userHandle;
        private final List<String> prevWarnings;

    @Override
      public Step4 nextStep() {
        return new Step4(username, userHandle, credential(), allWarnings());
      }

    @Override
    public void validate() {
        if (!maybeCredential().isPresent()) {
            throw new IllegalArgumentException(String.format(
                "Unknown credential. Credential ID: %s, user handle: %s", response.getId(), userHandle
            ));
        }
    }

    private Optional<RegisteredCredential> maybeCredential() {
        return credentialRepository.lookup(response.getId(), userHandle);
    }

    public RegisteredCredential credential() {
        return maybeCredential().get();
    }
  }

  @Value
  public class Step4 implements Step<Step3, Step5> {

      private final String username;
    private final String userHandle;
      private final RegisteredCredential credential;
      private final List<String> prevWarnings;

    @Override public void validate() {
       if (clientData().length == 0) {
           throw new IllegalArgumentException("Missing client data.");
       }

        if (authenticatorData().length == 0) {
           throw new IllegalArgumentException("Missing authenticator data.");
        }

        if (signature().length == 0) {
           throw new IllegalArgumentException("Missing signature.");
        }
    }

    @Override
    public Step5 nextStep() {
        return new Step5(username, userHandle, credential, allWarnings());
    }

    public byte[] authenticatorData() {
        return response.getResponse().getAuthenticatorData();
    }

    public byte[] clientData() {
        return response.getResponse().getClientDataJSON();
    }
    public byte[] signature() {
        return response.getResponse().getSignature();
    }
  }

  @Value
  public class Step5 implements Step<Step4, Step6> {
      private final String username;
      private final String userHandle;
      private final RegisteredCredential credential;
      private final List<String> prevWarnings;

    // Nothing to do
    @Override public void validate() {}

    @Override public Step6 nextStep() {
        return new Step6(username, userHandle, credential, allWarnings());
    }
  }

  @Value
  public class Step6 implements Step<Step5, Step7> {
      private final String username;
      private final String userHandle;
      private final RegisteredCredential credential;
      private final List<String> prevWarnings;

    @Override
    public void validate() {
        if (clientData() == null) {
            throw new IllegalArgumentException("Missing client data.");
        }
    }

    @Override public Step7 nextStep() {
        return new Step7(username, userHandle, credential, clientData(), allWarnings());
    }

    public CollectedClientData clientData() {
        try {
            return response.getResponse().getCollectedClientData();
        } catch (IOException e) {
            throw new IllegalArgumentException("Client data is not valid JSON: " + response.getResponse().getClientDataJSONString());
        } catch (U2fBadInputException e) {
            throw new IllegalArgumentException("Malformed client data: " + response.getResponse().getClientDataJSONString());
        }
    }
  }

  @Value
  public class Step7 implements Step<Step6, Step8> {

      private final String username;
      private final String userHandle;
      private final RegisteredCredential credential;
      private final CollectedClientData clientData;
      private final List<String> prevWarnings;

      private List<String> warnings = new LinkedList<>();

      @Override
      public List<String> getWarnings() {
          return Collections.unmodifiableList(warnings);
      }

    @Override
    public void validate() {
      try {
          if (!
              CLIENT_DATA_TYPE.equals(clientData.getType())
          ) {
              final String message = String.format(
                  "The \"type\" in the client data must be exactly \"%s\", was: %s", CLIENT_DATA_TYPE, clientData.getType()
              );
              if (validateTypeAttribute) {
                  throw new IllegalArgumentException(message);
              } else {
                  warnings.add(message);
              }
          }
      } catch (NullPointerException e) {
          final String message = "Missing \"type\" attribute in the client data.";
          if (validateTypeAttribute) {
              throw new IllegalArgumentException(message);
          } else {
              warnings.add(message);
          }
      }
    }

    @Override
    public Step8 nextStep() {
        return new Step8(username, userHandle, credential, allWarnings());
    }
  }

  @Value
  public class Step8 implements Step<Step7, Step9> {
      private final String username;
      private final String userHandle;
      private final RegisteredCredential credential;
      private final List<String> prevWarnings;

    @Override
    public void validate() {
        try {
            if (false == Arrays.equals(response.getResponse().getCollectedClientData().getChallenge(), request.getPublicKeyCredentialRequestOptions().getChallenge())) {
                throw new IllegalArgumentException("Incorrect challenge.");
            }
        } catch (U2fBadInputException | IOException e) {
            throw new IllegalArgumentException("Failed to read challenge from client data: " + response.getResponse().getClientDataJSONString());
        }
    }

    @Override
    public Step9 nextStep() {
        return new Step9(username, userHandle, credential, allWarnings());
    }
  }

  @Value
  public class Step9 implements Step<Step8, Step10> {
      private final String username;
        private final String userHandle;
      private final RegisteredCredential credential;
      private final List<String> prevWarnings;

    @Override
    public void validate() {
        final String responseOrigin;
        try {
            responseOrigin = response.getResponse().getCollectedClientData().getOrigin();
        } catch (IOException | U2fBadInputException e) {
            throw new IllegalArgumentException("Failed to read origin from client data: " + response.getResponse().getClientDataJSONString());
        }

        if (origins.stream().noneMatch(o -> o.equals(responseOrigin))) {
            throw new IllegalArgumentException("Incorrect origin: " + responseOrigin);
        }
    }

    @Override
    public Step10 nextStep() {
        return new Step10(username, userHandle, credential, allWarnings());
    }
  }

  @Value
  public class Step10 implements Step<Step9, Step11> {
      private final String username;
        private final String userHandle;
      private final RegisteredCredential credential;
      private final List<String> prevWarnings;

    @Override
    public void validate() {
        try {
            TokenBindingValidator.validate(response.getResponse().getCollectedClientData().getTokenBinding(), callerTokenBindingId);
        } catch (IOException | U2fBadInputException e) {
            throw new IllegalArgumentException("Failed to read token binding info from client data" + response.getResponse().getClientDataJSONString());
        }
    }

    @Override
    public Step11 nextStep() {
        return new Step11(username, userHandle, credential, allWarnings());
    }
  }

  @Value
  public class Step11 implements Step<Step10, Step12> {
      private final String username;
        private final String userHandle;
      private final RegisteredCredential credential;
      private final List<String> prevWarnings;

    @Override
    public void validate() {
        if (false == Arrays.equals(response.getResponse().getParsedAuthenticatorData().getRpIdHash(), crypto.hash(rpId))) {
            throw new IllegalArgumentException("Wrong RP ID hash.");
        }
    }

    @Override
      public Step12 nextStep() {
        return new Step12(username, userHandle, credential, allWarnings());
      }
  }

  @Value
  public class Step12 implements Step<Step11, Step13> {
      private final String username;
        private final String userHandle;
      private final RegisteredCredential credential;
      private final List<String> prevWarnings;

    @Override
    public void validate() {
      if (request.getPublicKeyCredentialRequestOptions().getUserVerification() == UserVerificationRequirement.REQUIRED) {
          if (!
              response.getResponse().getParsedAuthenticatorData().getFlags().UV
          ) {
              throw new IllegalArgumentException("User Verification is required.");
          }
      }
    }
    @Override
      public Step13 nextStep() {
        return new Step13(username, userHandle, credential, allWarnings());
      }
  }

  @Value
  public class Step13 implements Step<Step12, Step14> {
      private final String username;
        private final String userHandle;
      private final RegisteredCredential credential;
      private final List<String> prevWarnings;

    @Override
    public void validate() {
      if (request.getPublicKeyCredentialRequestOptions().getUserVerification() != UserVerificationRequirement.REQUIRED) {
          if (!
              response.getResponse().getParsedAuthenticatorData().getFlags().UP
          ) {
              throw new IllegalArgumentException("User Presence is required.");
          }
      }
    }
    @Override
      public Step14 nextStep() {
        return new Step14(username, userHandle, credential, allWarnings());
      }
  }

  @Value
  public class Step14 implements Step<Step13, Step15> {
      private final String username;
        private final String userHandle;
      private final RegisteredCredential credential;
      private final List<String> prevWarnings;

    @Override
    public void validate() {
      if (!allowUnrequestedExtensions) {
        ExtensionsValidation.validate(request.getPublicKeyCredentialRequestOptions().getExtensions(), response);
      }
    }

    @Override
    public List<String> getWarnings() {
        try {
            ExtensionsValidation.validate(request.getPublicKeyCredentialRequestOptions().getExtensions(), response);
            return Collections.emptyList();
        } catch (Exception e) {
            return Collections.unmodifiableList(Collections.singletonList(e.getMessage()));
      }
    }
    @Override
      public Step15 nextStep() {
        return new Step15(username, userHandle, credential, allWarnings());
      }
  }

  @Value
  public class Step15 implements Step<Step14, Step16> {
      private final String username;
        private final String userHandle;
      private final RegisteredCredential credential;
      private final List<String> prevWarnings;

    @Override
    public void validate() {
        if (clientDataJsonHash() == null) {
            throw new IllegalArgumentException("Failed to compute hash of client data");
        }
    }
    @Override
      public Step16 nextStep() {
        return new Step16(username, userHandle, credential, clientDataJsonHash(), allWarnings());
      }

        public byte[] clientDataJsonHash() {
            return crypto.hash(response.getResponse().getClientDataJSON());
        }
  }

  @Value
  public class Step16 implements Step<Step15, Step17> {
      private final String username;
      private final String userHandle;
      private final RegisteredCredential credential;
      private final byte[] clientDataJsonHash;
      private final List<String> prevWarnings;

    @Override
    public void validate() {
        try {
            crypto.checkSignature(
                credential.publicKey,
                signedBytes(),
                response.getResponse().getSignature()
            );
        } catch (U2fBadInputException e) {
            throw new IllegalArgumentException("Invalid assertion signature.");
        }
    }
    @Override
      public Step17 nextStep() {
        return new Step17(username, userHandle, allWarnings());
      }

    public byte[] signedBytes() {
        return org.bouncycastle.util.Arrays.concatenate(response.getResponse().getAuthenticatorData(), clientDataJsonHash);
    }
  }

  @Value
  public class Step17 implements Step<Step16, Finished> {
      private final String username;
      private final String userHandle;
      private final List<String> prevWarnings;

    @Override
    public void validate() {
      if (validateSignatureCounter) {
          if (! signatureCounterValid()) {
              throw new IllegalArgumentException(String.format(
                  "Signature counter must increase. Stored value: %s, received value: %s",
                  storedSignatureCountBefore(), assertionSignatureCount()
              ));
          }
      }
    }

    private boolean signatureCounterValid() {
      return assertionSignatureCount() == 0
          || assertionSignatureCount() > storedSignatureCountBefore();
    }

    @Override
      public Finished nextStep() {
        return new Finished(username, userHandle, assertionSignatureCount(), signatureCounterValid(), allWarnings());
      }

    private long storedSignatureCountBefore() {
        return credentialRepository.lookup(response.getId(), userHandle)
            .map(RegisteredCredential::getSignatureCount)
            .orElse(0L);
    }

    private long assertionSignatureCount() {
        return response.getResponse().getParsedAuthenticatorData().getSignatureCounter();
    }
  }

  @Value
  public class Finished implements Step<Step17, Finished> {
      private final String username;
        private final String userHandle;
      private final long assertionSignatureCount;
      private final boolean signatureCounterValid;
      private final List<String> prevWarnings;

    @Override
    public void validate() { /* No-op */ }

    @Override public boolean isFinished() { return true; }

    @Override
      public Finished nextStep() {
        return this;
      }

    @Override
    public Optional<AssertionResult> result() {
        try {
            return Optional.of(AssertionResult.builder()
                .credentialId(response.getRawId())
                .signatureCount(assertionSignatureCount)
                .signatureCounterValid(signatureCounterValid)
                .success(true)
                .username(username)
                .userHandle(U2fB64Encoding.decode(userHandle))
                .warnings(allWarnings())
                .build()
            );
        } catch (U2fBadInputException e) {
            throw ExceptionUtil.wrapAndLog(log, "Failed to decode user handle to bytes: " + userHandle, e);
        }
    }

  }

}
