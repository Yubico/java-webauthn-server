package demo.webauthn;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.HashMultimap;
import com.google.common.collect.Multimap;
import com.yubico.u2f.attestation.MetadataService;
import com.yubico.u2f.crypto.BouncyCastleCrypto;
import com.yubico.u2f.crypto.ChallengeGenerator;
import com.yubico.u2f.crypto.RandomChallengeGenerator;
import com.yubico.u2f.data.messages.key.util.U2fB64Encoding;
import com.yubico.webauthn.RegistrationResult;
import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.data.PublicKey$;
import com.yubico.webauthn.data.PublicKeyCredentialParameters;
import com.yubico.webauthn.data.RelyingPartyIdentity;
import com.yubico.webauthn.data.UserIdentity;
import java.io.IOException;
import java.time.Clock;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import lombok.Value;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import scala.util.Either;
import scala.util.Left;
import scala.util.Right;
import scala.util.Try;

public class WebAuthnServer {
    private static final Logger logger = LoggerFactory.getLogger(WebAuthnServer.class);

    public static final String ORIGIN = "https://localhost:8443";

    private final Map<String, AssertionRequest> assertRequestStorage = new HashMap<String, AssertionRequest>();
    private final Map<String, RegistrationRequest> registerRequestStorage = new HashMap<String, RegistrationRequest>();
    private final Multimap<String, CredentialRegistration> userStorage = HashMultimap.create();
    private final InMemoryCredentialRepository credentialRepository = new InMemoryCredentialRepository();

    private final ChallengeGenerator challengeGenerator = new RandomChallengeGenerator();

    private final MetadataService metadataService = new MetadataService();

    private final Clock clock = Clock.systemDefaultZone();
    private final ObjectMapper jsonMapper = new ScalaJackson().get();


    private final RelyingParty rp = new RelyingParty(
        new RelyingPartyIdentity("Yubico WebAuthn demo", "localhost", Optional.empty()),
        challengeGenerator,
        Arrays.asList(new PublicKeyCredentialParameters(-7L, PublicKey$.MODULE$)),
        Arrays.asList(ORIGIN),
        Optional.empty(),
        new BouncyCastleCrypto(),
        true,
        credentialRepository,
        Optional.of(metadataService)
    );

    public RegistrationRequest startRegistration(String username, String credentialNickname) {
        logger.info("startRegistration username: {}, credentialNickname: {}", username, credentialNickname);
        RegistrationRequest request = new RegistrationRequest(
            username,
            credentialNickname,
            U2fB64Encoding.encode(challengeGenerator.generateChallenge()),
            rp.startRegistration(
                new UserIdentity(username, username, username, Optional.empty()),
                Optional.of(
                    userStorage.get(username).stream()
                        .map(registration -> registration.getRegistration().keyId())
                        .collect(Collectors.toList())
                ),
                Optional.empty()
            )
        );
        registerRequestStorage.put(request.getRequestId(), request);
        return request;
    }

    @Value
    public static class SuccessfulRegistrationResult {
        RegistrationRequest request;
        RegistrationResponse response;
        CredentialRegistration registration;
    }

    public Either<List<String>, SuccessfulRegistrationResult> finishRegistration(String responseJson) {
        logger.info("finishRegistration responseJson: {}", responseJson);
        RegistrationResponse response = null;
        try {
            response = jsonMapper.readValue(responseJson, RegistrationResponse.class);
        } catch (IOException e) {
            logger.info("fail finishRegistration responseJson: {}", responseJson, e);
            return Left.apply(Arrays.asList("Credential creation failed!", "Failed to decode response object.", e.getMessage()));
        }

        RegistrationRequest request = registerRequestStorage.remove(response.getRequestId());

        if (request == null) {
            logger.info("fail finishRegistration responseJson: {}", responseJson);
            return Left.apply(Arrays.asList("Credential creation failed!", "No such registration in progress."));
        } else {
            Try<RegistrationResult> registrationTry = rp.finishRegistration(
                request.getMakePublicKeyCredentialOptions(),
                response.getCredential(),
                Optional.empty()
            );

            if (registrationTry.isSuccess()) {
                return Right.apply(
                    new SuccessfulRegistrationResult(
                        request,
                        response,
                        addRegistration(
                            request.getUsername(),
                            request.getCredentialNickname(),
                            registrationTry.get()
                        )
                    )
                );
            } else {
                logger.info("fail finishRegistration responseJson: {}", responseJson, registrationTry.failed().get());
                return Left.apply(Arrays.asList("Credential creation failed!", registrationTry.failed().get().getMessage()));
            }

        }
    }

    public AssertionRequest startAuthentication(String username) {
        logger.info("startAuthentication username: {}", username);
        AssertionRequest request = new AssertionRequest(
            username,
            U2fB64Encoding.encode(challengeGenerator.generateChallenge()),
            rp.startAssertion(
                Optional.of(
                    userStorage.get(username).stream()
                        .map(credentialRegistration -> credentialRegistration.getRegistration().keyId())
                        .collect(Collectors.toList())
                ),
                Optional.empty()
            )
        );

        assertRequestStorage.put(request.getRequestId(), request);

        return request;
    }

    @Value
    public static class SuccessfulAuthenticationResult {
        AssertionRequest request;
        AssertionResponse response;
        Collection<CredentialRegistration> registrations;
    }

    public Either<List<String>, SuccessfulAuthenticationResult> finishAuthentication(String responseJson) {
        logger.info("finishAuthentication responseJson: {}", responseJson);

        AssertionResponse response = null;
        try {
            response = jsonMapper.readValue(responseJson, AssertionResponse.class);
        } catch (IOException e) {
            logger.debug("Failed to decode response object", e);
            return Left.apply(Arrays.asList("Assertion failed!", "Failed to decode response object.", e.getMessage()));
        }

        AssertionRequest request = assertRequestStorage.remove(response.getRequestId());

        if (request == null) {
            return Left.apply(Arrays.asList("Credential creation failed!", "No such registration in progress."));
        } else {
            Try<Object> assertionTry = rp.finishAssertion(
                request.getPublicKeyCredentialRequestOptions(),
                response.getCredential(),
                Optional.empty()
            );

            if (assertionTry.isSuccess()) {
                if ((boolean) assertionTry.get()) {
                    return Right.apply(
                        new SuccessfulAuthenticationResult(
                            request,
                            response,
                            userStorage.get(request.getUsername())
                        )
                    );
                } else {
                    return Left.apply(Arrays.asList("Assertion failed: Invalid assertion."));
                }

            } else {
                logger.debug("Assertion failed", assertionTry.failed().get());
                return Left.apply(Arrays.asList("Assertion failed!", assertionTry.failed().get().getMessage()));
            }

        }
    }

    public Either<List<String>, CredentialRegistration> deregisterCredential(String username, String credentialId) {
        logger.info("deregisterCredential username: {}, credentialId: {}", username, credentialId);

        if (username == null || username.isEmpty()) {
            return Left.apply(Arrays.asList("Username must not be empty."));
        }

        if (credentialId == null || credentialId.isEmpty()) {
            return Left.apply(Arrays.asList("Credential ID must not be empty."));
        }

        Optional<CredentialRegistration> credReg = userStorage.get(username).stream()
            .filter(credentialRegistration -> credentialRegistration.getRegistration().keyId().idBase64().equals(credentialId))
            .findAny();

        if (credReg.isPresent()) {
            userStorage.remove(username, credReg.get());
            credentialRepository.remove(credentialId);
            return Right.apply(credReg.get());
        } else {
            return Left.apply(Arrays.asList("Credential ID not registered:" + credentialId));
        }
    }

    private CredentialRegistration addRegistration(String username, String nickname, RegistrationResult registration) {
        CredentialRegistration reg = new CredentialRegistration(username, nickname, clock.instant(), registration);
        logger.info(
            "Adding registration: username: {}, nickname: {}, registration: {}, credentialId: {}, public key cose: {}",
            username,
            nickname,
            registration,
            registration.keyId().idBase64(),
            registration.publicKeyCose()
        );
        userStorage.put(username, reg);
        credentialRepository.add(registration.keyId().idBase64(), registration.publicKeyCose());
        return reg;
    }
}
