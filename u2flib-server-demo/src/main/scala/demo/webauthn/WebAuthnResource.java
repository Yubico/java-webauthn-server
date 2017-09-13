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
import com.yubico.u2f.attestation.MetadataService;
import com.yubico.u2f.attestation.resolvers.SimpleResolver;
import com.yubico.u2f.crypto.BouncyCastleCrypto;
import com.yubico.u2f.crypto.ChallengeGenerator;
import com.yubico.u2f.crypto.RandomChallengeGenerator;
import com.yubico.u2f.data.messages.key.util.U2fB64Encoding;
import com.yubico.webauthn.CredentialRepository;
import com.yubico.webauthn.RegistrationResult;
import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.data.PublicKey$;
import com.yubico.webauthn.data.PublicKeyCredentialParameters;
import com.yubico.webauthn.data.RelyingPartyIdentity;
import com.yubico.webauthn.data.UserIdentity;
import demo.webauthn.view.FinishRegistrationView;
import demo.webauthn.view.RegistrationFailedView;
import demo.webauthn.view.RegistrationView;
import io.dropwizard.views.View;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import scala.collection.immutable.Vector;
import scala.util.Try;

@Path("/webauthn")
@Produces(MediaType.TEXT_HTML)
public class WebAuthnResource {

    public static final String ORIGIN = "localhost";

    private final Map<String, RegistrationRequest> requestStorage = new HashMap<String, RegistrationRequest>();
    private final Multimap<String, CredentialRegistration> userStorage = HashMultimap.create();

    private final ChallengeGenerator challengeGenerator = new RandomChallengeGenerator();

    private final MetadataService metadataService = new MetadataService();
    private final MetadataResolver metadataResolver = new SimpleResolver();

    private final RelyingParty rp = new RelyingParty(
        new RelyingPartyIdentity("Yubico WebAuthn demo", "localhost", Optional.empty()),
        challengeGenerator,
        Arrays.asList(new PublicKeyCredentialParameters(-7L, PublicKey$.MODULE$)),
        ORIGIN,
        Optional.empty(),
        new BouncyCastleCrypto(),
        true,
        new CredentialRepository() {
            @Override
            public Optional<java.security.PublicKey> lookup(String credentialId) {
                return null;
            }
            @Override
            public Optional<java.security.PublicKey> lookup(Vector<Object> credentialId) { return null; }
        },
        Optional.of(metadataResolver)
    );

    private final ObjectMapper jsonMapper = new ScalaJackson().get();

    @Path("startRegistration")
    @GET
    public View startRegistration(@QueryParam("username") String username) throws JsonProcessingException {
        RegistrationRequest request = new RegistrationRequest(
            username,
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
        requestStorage.put(request.getRequestId(), request);
        return new RegistrationView(username, request.getRequestId(), jsonMapper.writeValueAsString(request));
    }

    @Path("finishRegistration")
    @POST
    public View finishRegistration(@FormParam("response") String responseJson) throws CertificateException, NoSuchFieldException, JsonProcessingException {
        RegistrationResponse response = null;
        try {
            response = jsonMapper.readValue(responseJson, RegistrationResponse.class);
        } catch (IOException e) {
            return new RegistrationFailedView("Failed to decode response object.");
        }

        RegistrationRequest request = requestStorage.remove(response.getRequestId());

        if (request == null) {
            return new RegistrationFailedView("No such registration in progress.");
        } else {
            Try<RegistrationResult> registrationTry = rp.finishRegistration(
                request.getMakePublicKeyCredentialOptions(),
                response.getCredential(),
                Optional.empty()
            );

            if (registrationTry.isSuccess()) {
                RegistrationResult registration = registrationTry.get();

                return new FinishRegistrationView(addRegistration(request.getUsername(), registration), jsonMapper.writeValueAsString(request), response, jsonMapper.writeValueAsString(response));
            } else {
                return new RegistrationFailedView(registrationTry.failed().get());
            }

        }
    }

    @Path("startAuthentication")
    @GET
    public View startAuthentication(@QueryParam("username") String username) {
        // try {
            // SignRequestData signRequestData = u2f.startSignature(APP_ID, getRegistrations(username));
            // requestStorage.put(signRequestData.getRequestId(), signRequestData.toJson());
            // return new AuthenticationView(signRequestData, username);
        // } catch (NoEligibleDevicesException e) {
            // return new AuthenticationView(new SignRequestData(APP_ID, "", Collections.<SignRequest>emptyList()), username);
        // }
        return null;
    }

    @Path("finishAuthentication")
    @POST
    public View finishAuthentication(@FormParam("tokenResponse") String response,
                                     @FormParam("username") String username) {
        // SignResponse signResponse = SignResponse.fromJson(response);
        // SignRequestData authenticateRequest = SignRequestData.fromJson(requestStorage.remove(signResponse.getRequestId()));
        // DeviceRegistration registration = null;
        // try {
            // registration = u2f.finishSignature(authenticateRequest, signResponse, getRegistrations(username));
        // } catch (DeviceCompromisedException e) {
            // registration = e.getDeviceRegistration();
            // return new FinishAuthenticationView(false, "Device possibly compromised and therefore blocked: " + e.getMessage());
        // } finally {
            // userStorage.getUnchecked(username).put(registration.getKeyHandle(), registration.toJson());
        // }
        // return new FinishAuthenticationView(true);
        return null;
    }

    private CredentialRegistration addRegistration(String username, RegistrationResult registration) {
        CredentialRegistration reg = new CredentialRegistration(username, registration);
        userStorage.put(username, reg);
        return reg;
    }
}
