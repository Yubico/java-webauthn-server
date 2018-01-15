package demo;

import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.MediaType;

import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import com.yubico.u2f.U2F;
import com.yubico.u2f.attestation.Attestation;
import com.yubico.u2f.attestation.MetadataService;
import com.yubico.u2f.data.DeviceRegistration;
import com.yubico.u2f.data.messages.SignRequest;
import com.yubico.u2f.data.messages.SignRequestData;
import com.yubico.u2f.data.messages.SignResponse;
import com.yubico.u2f.data.messages.RegisterRequestData;
import com.yubico.u2f.data.messages.RegisterResponse;
import com.yubico.u2f.exceptions.DeviceCompromisedException;
import com.yubico.u2f.exceptions.NoEligibleDevicesException;
import com.yubico.u2f.exceptions.U2fAuthenticationException;
import com.yubico.u2f.exceptions.U2fBadConfigurationException;
import com.yubico.u2f.exceptions.U2fBadInputException;
import com.yubico.u2f.exceptions.U2fRegistrationException;
import demo.view.AuthenticationView;
import demo.view.FinishAuthenticationView;
import demo.view.FinishRegistrationView;
import demo.view.RegistrationView;
import io.dropwizard.views.View;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Path("/")
@Produces(MediaType.TEXT_HTML)
public class Resource {

    public static final String APP_ID = "https://localhost:8443";

    private final Map<String, String> requestStorage = new HashMap<String, String>();
    private final LoadingCache<String, Map<String, String>> userStorage = CacheBuilder.newBuilder().build(new CacheLoader<String, Map<String, String>>() {
        @Override
        public Map<String, String> load(String key) throws Exception {
            return new HashMap<String, String>();
        }
    });
    private final U2F u2f = new U2F();
    private final MetadataService metadataService = new MetadataService();

    @Path("startRegistration")
    @GET
    public View startRegistration(@QueryParam("username") String username) throws U2fBadConfigurationException, U2fBadInputException {
        RegisterRequestData registerRequestData = u2f.startRegistration(APP_ID, getRegistrations(username));
        requestStorage.put(registerRequestData.getRequestId(), registerRequestData.toJson());
        return new RegistrationView(registerRequestData.toJson(), username);
    }

    @Path("finishRegistration")
    @POST
    public View finishRegistration(@FormParam("tokenResponse") String response, @FormParam("username") String username) throws CertificateException, U2fBadInputException, U2fRegistrationException {
        RegisterResponse registerResponse = RegisterResponse.fromJson(response);
        RegisterRequestData registerRequestData = RegisterRequestData.fromJson(requestStorage.remove(registerResponse.getRequestId()));
        DeviceRegistration registration = u2f.finishRegistration(registerRequestData, registerResponse);

        Attestation attestation = metadataService.getAttestation(registration.getAttestationCertificate());

        addRegistration(username, registration);

        return new FinishRegistrationView(attestation, registration);
    }

    @Path("startAuthentication")
    @GET
    public View startAuthentication(@QueryParam("username") String username) throws U2fBadConfigurationException, U2fBadInputException {
        try {
            SignRequestData signRequestData = u2f.startSignature(APP_ID, getRegistrations(username));
            requestStorage.put(signRequestData.getRequestId(), signRequestData.toJson());
            return new AuthenticationView(signRequestData, username);
        } catch (NoEligibleDevicesException e) {
            return new AuthenticationView(new SignRequestData(APP_ID, "", Collections.<SignRequest>emptyList()), username);
        }
    }

    @Path("finishAuthentication")
    @POST
    public View finishAuthentication(@FormParam("tokenResponse") String response,
                                       @FormParam("username") String username) throws U2fBadInputException {
        SignResponse signResponse = SignResponse.fromJson(response);
        SignRequestData authenticateRequest = SignRequestData.fromJson(requestStorage.remove(signResponse.getRequestId()));
        DeviceRegistration registration = null;
        try {
            registration = u2f.finishSignature(authenticateRequest, signResponse, getRegistrations(username));
        } catch (DeviceCompromisedException e) {
            registration = e.getDeviceRegistration();
            return new FinishAuthenticationView(false, "Device possibly compromised and therefore blocked: " + e.getMessage());
        } catch (U2fAuthenticationException e) {
            return new FinishAuthenticationView(false, "Authentication failed: " + e.getCause().getMessage());
        } finally {
            userStorage.getUnchecked(username).put(registration.getKeyHandle(), registration.toJson());
        }
        return new FinishAuthenticationView(true);
    }

    private Iterable<DeviceRegistration> getRegistrations(String username) throws U2fBadInputException {
        List<DeviceRegistration> registrations = new ArrayList<DeviceRegistration>();
        for (String serialized : userStorage.getUnchecked(username).values()) {
            registrations.add(DeviceRegistration.fromJson(serialized));
        }
        return registrations;
    }

    private void addRegistration(String username, DeviceRegistration registration) {
        userStorage.getUnchecked(username).put(registration.getKeyHandle(), registration.toJson());
    }
}
