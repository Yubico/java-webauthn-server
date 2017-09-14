package demo.webauthn;

import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.MediaType;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.HashMultimap;
import com.google.common.collect.Multimap;
import com.yubico.u2f.attestation.MetadataResolver;
import com.yubico.u2f.attestation.resolvers.SimpleResolver;
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
import demo.webauthn.view.AssertionView;
import demo.webauthn.view.FailureView;
import demo.webauthn.view.FinishAssertionView;
import demo.webauthn.view.FinishRegistrationView;
import demo.webauthn.view.RegistrationView;
import io.dropwizard.views.View;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.time.Clock;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import scala.util.Try;

@Path("/webauthn")
@Produces(MediaType.TEXT_HTML)
public class WebAuthnResource {

    private static final Logger logger = LoggerFactory.getLogger(WebAuthnResource.class);

    public static final String ORIGIN = "localhost";

    private final Map<String, AssertionRequest> assertRequestStorage = new HashMap<String, AssertionRequest>();
    private final Map<String, RegistrationRequest> registerRequestStorage = new HashMap<String, RegistrationRequest>();
    private final Multimap<String, CredentialRegistration> userStorage = HashMultimap.create();
    private final InMemoryCredentialRepository credentialRepository = new InMemoryCredentialRepository();

    private final ChallengeGenerator challengeGenerator = new RandomChallengeGenerator();

    private final MetadataResolver metadataResolver = new SimpleResolver();

    private final Clock clock = Clock.systemDefaultZone();
    private final ObjectMapper jsonMapper = new ScalaJackson().get();


    private final RelyingParty rp = new RelyingParty(
        new RelyingPartyIdentity("Yubico WebAuthn demo", "localhost", Optional.empty()),
        challengeGenerator,
        Arrays.asList(new PublicKeyCredentialParameters(-7L, PublicKey$.MODULE$)),
        ORIGIN,
        Optional.empty(),
        new BouncyCastleCrypto(),
        true,
        credentialRepository,
        Optional.of(metadataResolver)
    );

    @Path("startRegistration")
    @GET
    public View startRegistration(@QueryParam("username") String username, @QueryParam("credentialNickname") String credentialNickname) throws JsonProcessingException {
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
        return new RegistrationView(username, request.getRequestId(), jsonMapper.writeValueAsString(request));
    }

    @Path("finishRegistration")
    @POST
    public View finishRegistration(@FormParam("response") String responseJson) throws CertificateException, NoSuchFieldException, JsonProcessingException {
        RegistrationResponse response = null;
        try {
            response = jsonMapper.readValue(responseJson, RegistrationResponse.class);
        } catch (IOException e) {
            return new FailureView("Credential creation failed!", "Failed to decode response object.", e.getMessage());
        }

        RegistrationRequest request = registerRequestStorage.remove(response.getRequestId());

        if (request == null) {
            return new FailureView("Credential creation failed!", "No such registration in progress.");
        } else {
            Try<RegistrationResult> registrationTry = rp.finishRegistration(
                request.getMakePublicKeyCredentialOptions(),
                response.getCredential(),
                Optional.empty()
            );

            if (registrationTry.isSuccess()) {
                RegistrationResult registration = registrationTry.get();

                return new FinishRegistrationView(
                    addRegistration(
                        request.getUsername(),
                        request.getCredentialNickname(),
                        registration
                    ),
                    jsonMapper.writeValueAsString(request),
                    response,
                    jsonMapper.writeValueAsString(response)
                );
            } else {
                return new FailureView("Credential creation failed!", registrationTry.failed().get().getMessage());
            }

        }
    }

    @Path("startAuthentication")
    @GET
    public View startAuthentication(@QueryParam("username") String username) throws JsonProcessingException {
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

        return new AssertionView(username, request.getRequestId(), jsonMapper.writeValueAsString(request));
    }

    @Path("finishAuthentication")
    @POST
    public View finishAuthentication(@FormParam("response") String responseJson) throws JsonProcessingException {
        AssertionResponse response = null;
        try {
            response = jsonMapper.readValue(responseJson, AssertionResponse.class);
        } catch (IOException e) {
            logger.debug("Failed to decode response object", e);
            return new FailureView("Assertion failed!", "Failed to decode response object.", e.getMessage());
        }

        AssertionRequest request = assertRequestStorage.remove(response.getRequestId());

        if (request == null) {
            return new FailureView("Credential creation failed!", "No such registration in progress.");
        } else {
            Try<Object> assertionTry = rp.finishAssertion(
                request.getPublicKeyCredentialRequestOptions(),
                response.getCredential(),
                Optional.empty()
            );

            if (assertionTry.isSuccess()) {
                if ((boolean) assertionTry.get()) {
                    return new FinishAssertionView(
                        jsonMapper.writeValueAsString(request),
                        jsonMapper.writeValueAsString(response),
                        jsonMapper.writeValueAsString(userStorage.get(request.getUsername()))
                    );
                } else {
                    return new FailureView("Assertion failed: Invalid assertion.");
                }

            } else {
                logger.debug("Assertion failed", assertionTry.failed().get());
                return new FailureView("Assertion failed!", assertionTry.failed().get().getMessage());
            }

        }
    }

    private CredentialRegistration addRegistration(String username, String nickname, RegistrationResult registration) {
        CredentialRegistration reg = new CredentialRegistration(username, nickname, clock.instant(), registration);
        userStorage.put(username, reg);
        credentialRepository.add(registration.keyId().idBase64(), registration.publicKeyCose());
        return reg;
    }
}
