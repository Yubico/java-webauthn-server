package demo.webauthn;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.base.Charsets;
import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.google.common.io.CharStreams;
import com.google.common.io.Closeables;
import com.yubico.attestation.MetadataResolver;
import com.yubico.attestation.MetadataService;
import com.yubico.attestation.resolvers.CompositeResolver;
import com.yubico.attestation.resolvers.SimpleResolver;
import com.yubico.attestation.resolvers.SimpleResolverWithEquality;
import com.yubico.util.Either;
import com.yubico.webauthn.ChallengeGenerator;
import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.data.AssertionResult;
import com.yubico.webauthn.data.AttestationConveyancePreference;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.FinishAssertionOptions;
import com.yubico.webauthn.data.FinishRegistrationOptions;
import com.yubico.webauthn.data.PublicKeyCredentialParameters;
import com.yubico.webauthn.data.RegistrationResult;
import com.yubico.webauthn.data.RelyingPartyIdentity;
import com.yubico.webauthn.data.StartAssertionOptions;
import com.yubico.webauthn.data.StartRegistrationOptions;
import com.yubico.webauthn.data.UserIdentity;
import com.yubico.webauthn.impl.RandomChallengeGenerator;
import com.yubico.webauthn.impl.WebAuthnCodecs;
import demo.webauthn.data.AssertionRequest;
import demo.webauthn.data.AssertionResponse;
import demo.webauthn.data.CredentialRegistration;
import demo.webauthn.data.RegistrationRequest;
import demo.webauthn.data.RegistrationResponse;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.cert.CertificateException;
import java.time.Clock;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;
import java.util.function.Supplier;
import lombok.NonNull;
import lombok.Value;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class WebAuthnServer {
    private static final Logger logger = LoggerFactory.getLogger(WebAuthnServer.class);

    private final Cache<ByteArray, AssertionRequest> assertRequestStorage;
    private final Cache<ByteArray, RegistrationRequest> registerRequestStorage;
    private final RegistrationStorage userStorage;
    private final Cache<AssertionRequest, AuthenticatedAction> authenticatedActions = newCache();

    private final ChallengeGenerator challengeGenerator = new RandomChallengeGenerator();

    private final MetadataService metadataService = new MetadataService(
        new CompositeResolver(Arrays.asList(
            MetadataService.createDefaultMetadataResolver(),
            createExtraMetadataResolver()
        ))
    );

    private final Clock clock = Clock.systemDefaultZone();
    private final ObjectMapper jsonMapper = WebAuthnCodecs.json();

    private final RelyingParty rp;

    public WebAuthnServer() {
        this(new InMemoryRegistrationStorage(), newCache(), newCache(), Config.getRpIdentity(), Config.getOrigins());
    }

    public WebAuthnServer(RegistrationStorage userStorage, Cache<ByteArray, RegistrationRequest> registerRequestStorage, Cache<ByteArray, AssertionRequest> assertRequestStorage, RelyingPartyIdentity rpIdentity, List<String> origins) {
        this.userStorage = userStorage;
        this.registerRequestStorage = registerRequestStorage;
        this.assertRequestStorage = assertRequestStorage;

        rp = RelyingParty.builder()
            .rp(rpIdentity)
            .preferredPubkeyParams(Collections.singletonList(PublicKeyCredentialParameters.ES256))
            .origins(origins)
            .attestationConveyancePreference(Optional.of(AttestationConveyancePreference.DIRECT))
            .credentialRepository(this.userStorage)
            .metadataService(Optional.of(metadataService))
            .allowMissingTokenBinding(true)
            .allowUnrequestedExtensions(true)
            .allowUntrustedAttestation(true)
            .validateSignatureCounter(true)
            .validateTypeAttribute(false)
            .build();
    }

    /**
     * Create a {@link MetadataResolver} with additional metadata for unreleased YubiKey Preview devices.
     */
    private static MetadataResolver createExtraMetadataResolver() {
        SimpleResolver resolver = new SimpleResolverWithEquality();
        InputStream is = null;
        try {
            is = WebAuthnServer.class.getResourceAsStream("/preview-metadata.json");
            resolver.addMetadata(CharStreams.toString(new InputStreamReader(is, Charsets.UTF_8)));
        } catch (IOException | CertificateException e) {
            logger.error("createDefaultMetadataResolver failed", e);
        } finally {
            Closeables.closeQuietly(is);
        }
        return resolver;
    }

    private static <K, V> Cache<K, V> newCache() {
        return CacheBuilder.newBuilder()
            .maximumSize(100)
            .expireAfterAccess(10, TimeUnit.MINUTES)
            .build();
    }

    public Either<String, RegistrationRequest> startRegistration(
        @NonNull String username,
        @NonNull String displayName,
        Optional<String> credentialNickname,
        boolean requireResidentKey
    ) {
        logger.trace("startRegistration username: {}, credentialNickname: {}", username, credentialNickname);

        if (userStorage.getRegistrationsByUsername(username).isEmpty()) {
            final ByteArray userId = new ByteArray(challengeGenerator.generateChallenge());

            RegistrationRequest request = new RegistrationRequest(
                username,
                credentialNickname,
                new ByteArray(challengeGenerator.generateChallenge()),
                rp.startRegistration(
                    StartRegistrationOptions.builder()
                        .user(UserIdentity.builder()
                            .name(username)
                            .displayName(displayName)
                            .id(userId)
                            .build()
                        )
                        .excludeCredentials(Optional.of(userStorage.getCredentialIdsForUsername(username)))
                        .requireResidentKey(requireResidentKey)
                        .build()
                )
            );
            registerRequestStorage.put(request.getRequestId(), request);
            return Either.right(request);
        } else {
            return Either.left("The username \"" + username + "\" is already registered.");
        }
    }

    public <T> Either<List<String>, AssertionRequest> startAddCredential(
        @NonNull String username,
        Optional<String> credentialNickname,
        boolean requireResidentKey,
        Function<RegistrationRequest, Either<List<String>, T>> whenAuthenticated
    ) {
        logger.trace("startAddCredential username: {}, credentialNickname: {}, requireResidentKey: {}", username, credentialNickname, requireResidentKey);

        if (username == null || username.isEmpty()) {
            return Either.left(Arrays.asList("username must not be empty."));
        }

        Collection<CredentialRegistration> registrations = userStorage.getRegistrationsByUsername(username);

        if (registrations.isEmpty()) {
            return Either.left(Arrays.asList("The username \"" + username + "\" is not registered."));
        } else {
            final UserIdentity existingUser = registrations.stream().findAny().get().getUserIdentity();

            AuthenticatedAction<T> action = (SuccessfulAuthenticationResult result) -> {
                RegistrationRequest request = new RegistrationRequest(
                    username,
                    credentialNickname,
                    new ByteArray(challengeGenerator.generateChallenge()),
                    rp.startRegistration(
                        StartRegistrationOptions.builder()
                            .user(existingUser)
                            .excludeCredentials(Optional.of(userStorage.getCredentialIdsForUsername(username)))
                            .requireResidentKey(requireResidentKey)
                            .build()
                    )
                );
                registerRequestStorage.put(request.getRequestId(), request);

                return whenAuthenticated.apply(request);
            };

            return startAuthenticatedAction(Optional.of(username), action);
        }
    }

    @Value
    public static class SuccessfulRegistrationResult {
        final boolean success = true;
        RegistrationRequest request;
        RegistrationResponse response;
        CredentialRegistration registration;
        boolean attestationTrusted;
    }

    public Either<List<String>, SuccessfulRegistrationResult> finishRegistration(String responseJson) {
        logger.trace("finishRegistration responseJson: {}", responseJson);
        RegistrationResponse response = null;
        try {
            response = jsonMapper.readValue(responseJson, RegistrationResponse.class);
        } catch (IOException e) {
            logger.error("JSON error in finishRegistration; responseJson: {}", responseJson, e);
            return Either.left(Arrays.asList("Registration failed!", "Failed to decode response object.", e.getMessage()));
        }

        RegistrationRequest request = registerRequestStorage.getIfPresent(response.getRequestId());
        registerRequestStorage.invalidate(response.getRequestId());

        if (request == null) {
            logger.debug("fail finishRegistration responseJson: {}", responseJson);
            return Either.left(Arrays.asList("Registration failed!", "No such registration in progress."));
        } else {
            try {
                RegistrationResult registration = rp.finishRegistration(
                    FinishRegistrationOptions.builder()
                        .request(request.getPublicKeyCredentialCreationOptions())
                        .response(response.getCredential())
                        .build()
                );

                return Either.right(
                    new SuccessfulRegistrationResult(
                        request,
                        response,
                        addRegistration(
                            request.getPublicKeyCredentialCreationOptions().getUser(),
                            request.getCredentialNickname(),
                            response,
                            registration
                        ),
                        registration.isAttestationTrusted()
                    )
                );
            } catch (Exception e) {
                logger.debug("fail finishRegistration responseJson: {}", responseJson, e);
                return Either.left(Arrays.asList("Registration failed!", e.getMessage()));
            }
        }
    }

    public Either<List<String>, AssertionRequest> startAuthentication(Optional<String> username) {
        logger.trace("startAuthentication username: {}", username);

        if (username.isPresent() && userStorage.getRegistrationsByUsername(username.get()).isEmpty()) {
            return Either.left(Arrays.asList("The username \"" + username.get() + "\" is not registered."));
        } else {
            AssertionRequest request = new AssertionRequest(
                new ByteArray(challengeGenerator.generateChallenge()),
                rp.startAssertion(
                    StartAssertionOptions.builder()
                        .username(username)
                        .build()
                )
            );

            assertRequestStorage.put(request.getRequestId(), request);

            return Either.right(request);
        }
    }

    @Value
    public static class SuccessfulAuthenticationResult {
        final boolean success = true;
        AssertionRequest request;
        AssertionResponse response;
        Collection<CredentialRegistration> registrations;
        List<String> warnings;
    }

    public Either<List<String>, SuccessfulAuthenticationResult> finishAuthentication(String responseJson) {
        logger.trace("finishAuthentication responseJson: {}", responseJson);

        final AssertionResponse response;
        try {
            response = jsonMapper.readValue(responseJson, AssertionResponse.class);
        } catch (IOException e) {
            logger.debug("Failed to decode response object", e);
            return Either.left(Arrays.asList("Assertion failed!", "Failed to decode response object.", e.getMessage()));
        }

        AssertionRequest request = assertRequestStorage.getIfPresent(response.getRequestId());
        assertRequestStorage.invalidate(response.getRequestId());

        if (request == null) {
            return Either.left(Arrays.asList("Assertion failed!", "No such assertion in progress."));
        } else {
            try {
                AssertionResult result = rp.finishAssertion(
                    FinishAssertionOptions.builder()
                        .request(request.getRequest())
                        .response(response.getCredential())
                        .build()
                );

                if (result.isSuccess()) {
                    try {
                        userStorage.updateSignatureCount(result);
                    } catch (Exception e) {
                        logger.error(
                            "Failed to update signature count for user \"{}\", credential \"{}\"",
                            result.getUsername(),
                            response.getCredential().getId(),
                            e
                        );
                    }

                    return Either.right(
                        new SuccessfulAuthenticationResult(
                            request,
                            response,
                            userStorage.getRegistrationsByUsername(result.getUsername()),
                            result.getWarnings()
                        )
                    );
                } else {
                    return Either.left(Arrays.asList("Assertion failed: Invalid assertion."));
                }
            } catch (Exception e) {
                logger.debug("Assertion failed", e);
                return Either.left(Arrays.asList("Assertion failed!", e.getMessage()));
            }
        }
    }

    public Either<List<String>, AssertionRequest> startAuthenticatedAction(Optional<String> username, AuthenticatedAction<?> action) {
        return startAuthentication(username)
            .map(request -> {
                synchronized (authenticatedActions) {
                    authenticatedActions.put(request, action);
                }
                return request;
            });
    }

    public Either<List<String>, ?> finishAuthenticatedAction(String responseJson) {
        return finishAuthentication(responseJson)
            .flatMap(result -> {
                AuthenticatedAction<?> action = authenticatedActions.getIfPresent(result.request);
                authenticatedActions.invalidate(result.request);
                if (action == null) {
                    return com.yubico.util.Either.left(Collections.singletonList(
                        "No action was associated with assertion request ID: " + result.getRequest().getRequestId()
                    ));
                } else {
                    return action.apply(result);
                }
            });
    }

    public <T> Either<List<String>, AssertionRequest> deregisterCredential(String username, ByteArray credentialId, Function<CredentialRegistration, T> resultMapper) {
        logger.trace("deregisterCredential username: {}, credentialId: {}", username, credentialId);

        if (username == null || username.isEmpty()) {
            return Either.left(Arrays.asList("Username must not be empty."));
        }

        if (credentialId == null || credentialId.getBytes().length == 0) {
            return Either.left(Arrays.asList("Credential ID must not be empty."));
        }

        AuthenticatedAction<T> action = (SuccessfulAuthenticationResult result) -> {
            Optional<CredentialRegistration> credReg = userStorage.getRegistrationByUsernameAndCredentialId(username, credentialId);

            if (credReg.isPresent()) {
                userStorage.removeRegistrationByUsername(username, credReg.get());
                return Either.right(resultMapper.apply(credReg.get()));
            } else {
                return Either.left(Arrays.asList("Credential ID not registered:" + credentialId));
            }
        };

        return startAuthenticatedAction(Optional.of(username), action);
    }

    public <T> Either<List<String>, T> deleteAccount(String username, Supplier<T> onSuccess) {
        logger.trace("deleteAccount username: {}", username);

        if (username == null || username.isEmpty()) {
            return Either.left(Arrays.asList("Username must not be empty."));
        }

        boolean removed = userStorage.removeAllRegistrations(username);

        if (removed) {
            return Either.right(onSuccess.get());
        } else {
            return Either.left(Arrays.asList("Username not registered:" + username));
        }
    }

    private CredentialRegistration addRegistration(
        UserIdentity userIdentity,
        Optional<String> nickname,
        RegistrationResponse response,
        RegistrationResult registration
    ) {
        CredentialRegistration reg = CredentialRegistration.builder()
            .userIdentity(userIdentity)
            .credentialNickname(nickname)
            .registrationTime(clock.instant())
            .registration(registration)
            .signatureCount(response.getCredential().getResponse().getAttestation().getAuthenticatorData().getSignatureCounter())
            .build();

        logger.debug(
            "Adding registration: user: {}, nickname: {}, registration: {}, credentialId: {}, public key cose: {}",
            userIdentity,
            nickname,
            registration,
            registration.getKeyId().getId(),
            registration.getPublicKeyCose()
        );
        userStorage.addRegistrationByUsername(userIdentity.getName(), reg);
        return reg;
    }
}
