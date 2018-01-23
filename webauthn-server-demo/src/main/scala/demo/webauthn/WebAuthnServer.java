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
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
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
    private final Map<AssertionRequest, AuthenticatedAction> authenticatedActions = new HashMap<>();

    private final ChallengeGenerator challengeGenerator = new RandomChallengeGenerator();

    private final MetadataService metadataService = new MetadataService();

    private final Clock clock = Clock.systemDefaultZone();
    private final ObjectMapper jsonMapper = new ScalaJackson().get();


    private final RelyingParty rp = new RelyingParty(
        new RelyingPartyIdentity("Yubico WebAuthn demo", "localhost", Optional.empty()),
        challengeGenerator,
        Arrays.asList(
            new PublicKeyCredentialParameters(-7L, PublicKey$.MODULE$),
            new PublicKeyCredentialParameters("ES256", PublicKey$.MODULE$) // TODO remove ES256
        ),
        Arrays.asList(ORIGIN),
        Optional.empty(),
        new BouncyCastleCrypto(),
        true,
        credentialRepository,
        Optional.of(metadataService),
        true,
        false
    );

    public RegistrationRequest startRegistration(String username, String displayName, String credentialNickname) {
        logger.trace("startRegistration username: {}, credentialNickname: {}", username, credentialNickname);

        byte[] userId = challengeGenerator.generateChallenge();

        RegistrationRequest request = new RegistrationRequest(
            username,
            credentialNickname,
            U2fB64Encoding.encode(challengeGenerator.generateChallenge()),
            rp.startRegistration(
                new UserIdentity(username, displayName, userId, Optional.empty()),
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
        final boolean success = true;
        RegistrationRequest request;
        RegistrationResponse response;
        CredentialRegistration registration;
    }

    public Either<List<String>, SuccessfulRegistrationResult> finishRegistration(String responseJson) {
        logger.trace("finishRegistration responseJson: {}", responseJson);
        RegistrationResponse response = null;
        try {
            response = jsonMapper.readValue(responseJson, RegistrationResponse.class);
        } catch (IOException e) {
            logger.error("JSON error in finishRegistration; responseJson: {}", responseJson, e);
            return Left.apply(Arrays.asList("Registration failed!", "Failed to decode response object.", e.getMessage()));
        }

        RegistrationRequest request = registerRequestStorage.remove(response.getRequestId());

        if (request == null) {
            logger.debug("fail finishRegistration responseJson: {}", responseJson);
            return Left.apply(Arrays.asList("Registration failed!", "No such registration in progress."));
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
                            request.getMakePublicKeyCredentialOptions().user().idBase64(),
                            response,
                            registrationTry.get()
                        )
                    )
                );
            } else {
                logger.debug("fail finishRegistration responseJson: {}", responseJson, registrationTry.failed().get());
                return Left.apply(Arrays.asList("Registration failed!", registrationTry.failed().get().getMessage()));
            }

        }
    }

    public AssertionRequest startAuthentication(String username) {
        logger.trace("startAuthentication username: {}", username);
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
        final boolean success = true;
        AssertionRequest request;
        AssertionResponse response;
        Collection<CredentialRegistration> registrations;
    }

    public Either<List<String>, SuccessfulAuthenticationResult> finishAuthentication(String responseJson) {
        logger.trace("finishAuthentication responseJson: {}", responseJson);

        final AssertionResponse response;
        try {
            response = jsonMapper.readValue(responseJson, AssertionResponse.class);
        } catch (IOException e) {
            logger.debug("Failed to decode response object", e);
            return Left.apply(Arrays.asList("Assertion failed!", "Failed to decode response object.", e.getMessage()));
        }

        AssertionRequest request = assertRequestStorage.remove(response.getRequestId());

        if (request == null) {
            return Left.apply(Arrays.asList("Assertion failed!", "No such assertion in progress."));
        } else {
            Optional<Boolean> credentialIsAllowed = request.getPublicKeyCredentialRequestOptions().allowCredentials().map(allowCredentials ->
                allowCredentials.stream().anyMatch(credential ->
                    credential.idBase64().equals(response.getCredential().id())
                )
            );

            boolean usernameOwnsCredential = userStorage.get(request.getUsername())
                .stream()
                .anyMatch(credentialRegistration ->
                    credentialRegistration.getRegistration().keyId().idBase64().equals(response.getCredential().id())
                )
            ;

            Optional<Boolean> userHandleOwnsCredential = Optional.ofNullable(response.getCredential().response().userHandleBase64())
                .map(userHandle ->
                    userStorage.values().stream()
                        .filter(credentialRegistration ->
                            userHandle.equals(credentialRegistration.getUserHandleBase64())
                        )
                        .anyMatch(credentialRegistration ->
                            response.getCredential().id().equals(credentialRegistration.getRegistration().keyId().idBase64())
                        )
                )
            ;

            if (credentialIsAllowed.isPresent() && !credentialIsAllowed.get()) {
                return Left.apply(Collections.singletonList(String.format(
                    "Credential is not allowed for this authentication: %s",
                    response.getCredential().id()
                )));
            } else if (!usernameOwnsCredential || (userHandleOwnsCredential.isPresent() && !userHandleOwnsCredential.get())) {
                return Left.apply(Collections.singletonList(String.format(
                    "User \"%s\" does not own credential: %s",
                    request.getUsername(),
                    response.getCredential().id()
                )));
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
    }

    public AssertionRequest startAuthenticatedAction(String username, AuthenticatedAction<?> action) {
        final AssertionRequest request = startAuthentication(username);
        synchronized (authenticatedActions) {
            authenticatedActions.put(request, action);
        }
        return request;
    }

    public Either<List<String>, ?> finishAuthenticatedAction(String responseJson) {
        return com.yubico.util.Either.fromScala(finishAuthentication(responseJson))
            .flatMap(result -> {
                AuthenticatedAction<?> action = authenticatedActions.remove(result.request);
                if (action == null) {
                    return com.yubico.util.Either.left(Collections.singletonList(
                        "No action was associated with assertion request ID: " + result.getRequest().getRequestId()
                    ));
                } else {
                    return com.yubico.util.Either.fromScala(action.apply(result));
                }
            })
            .toScala();
    }

    public <T> Either<List<String>, AssertionRequest> deregisterCredential(String username, String credentialId, Function<CredentialRegistration, T> resultMapper) {
        logger.trace("deregisterCredential username: {}, credentialId: {}", username, credentialId);

        if (username == null || username.isEmpty()) {
            return Left.apply(Arrays.asList("Username must not be empty."));
        }

        if (credentialId == null || credentialId.isEmpty()) {
            return Left.apply(Arrays.asList("Credential ID must not be empty."));
        }

        AuthenticatedAction<T> action = (SuccessfulAuthenticationResult result) -> {
            Optional<CredentialRegistration> credReg = userStorage.get(username).stream()
                .filter(credentialRegistration -> credentialRegistration.getRegistration().keyId().idBase64().equals(credentialId))
                .findAny();

            if (credReg.isPresent()) {
                userStorage.remove(username, credReg.get());
                credentialRepository.remove(credentialId);
                return Right.apply(resultMapper.apply(credReg.get()));
            } else {
                return Left.apply(Arrays.asList("Credential ID not registered:" + credentialId));
            }
        };

        return Right.apply(startAuthenticatedAction(username, action));
    }

    private CredentialRegistration addRegistration(String username, String nickname, String userHandleBase64, RegistrationResponse response, RegistrationResult registration) {
        CredentialRegistration reg = CredentialRegistration.builder()
            .username(username)
            .credentialNickname(nickname)
            .registrationTime(clock.instant())
            .registration(registration)
            .userHandleBase64(userHandleBase64)
            .signatureCount(response.getCredential().response().attestation().authenticatorData().signatureCounter())
            .build();

        logger.debug(
            "Adding registration: username: {}, nickname: {}, registration: {}, credentialId: {}, public key cose: {}",
            username,
            nickname,
            registration,
            registration.keyId().idBase64(),
            registration.publicKeyCose()
        );
        userStorage.put(username, reg);
        credentialRepository.add(registration.keyId().idBase64(), reg);
        return reg;
    }
}
