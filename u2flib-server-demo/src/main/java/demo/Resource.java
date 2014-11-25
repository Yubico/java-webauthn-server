package demo;

import com.google.common.base.Charsets;
import com.google.common.collect.*;
import com.google.common.io.Files;
import com.yubico.u2f.U2F;
import com.yubico.u2f.data.DeviceRegistration;
import com.yubico.u2f.data.messages.*;
import com.yubico.u2f.exceptions.U2fException;
import demo.view.AuthenticationView;
import demo.view.RegistrationView;
import io.dropwizard.views.View;

import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import java.io.File;
import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.*;

@Path("/")
@Produces(MediaType.TEXT_HTML)
public class Resource {

    public static final String SERVER_ADDRESS = "http://example.com:8080";
    public static final String NAVIGATION_MENU = "<h2>Navigation</h2><ul><li><a href='registerIndex'>Register</a></li><li><a href='loginIndex'>Login</a></li></ul>.";

    // In production, you want to store DeviceRegistrations persistently (e.g. in a database).
    private final Map<String, String> storage = new HashMap<String, String>();
    private final Multimap<String, String> userStorage = ArrayListMultimap.create();
    private final U2F u2f = new U2F();

    private Iterable<DeviceRegistration> getRegistrations(String username) {
        Collection<String> serializedRegistrations = userStorage.get(username);
        List<DeviceRegistration> registrations = new ArrayList<DeviceRegistration>();
        for(String serialized : serializedRegistrations) {
            registrations.add(DeviceRegistration.fromJson(serialized));
        }
        return registrations;
    }

    private void addRegistration(String username, DeviceRegistration registration) {
        userStorage.put(username, registration.toJson());
    }

    @Path("startRegistration")
    @GET
    public View startRegistration(@QueryParam("username") String username) {
        RegisterRequestData registerRequestData = u2f.startRegistration(SERVER_ADDRESS, getRegistrations(username));
        storage.put(registerRequestData.getRequestId(), registerRequestData.toJson());
        return new RegistrationView(registerRequestData.toJson(), username);
    }

    @Path("finishRegistration")
    @POST
    public String finishRegistration(@FormParam("tokenResponse") String response, @FormParam("username") String username)
            throws U2fException {
        RegisterResponse registerResponse = RegisterResponse.fromJson(response);
        RegisterRequestData registerRequestData = RegisterRequestData.fromJson(storage.get(registerResponse.getRequestId()));
        DeviceRegistration registration = u2f.finishRegistration(registerRequestData, registerResponse);
        addRegistration(username, registration);
        storage.remove(registerResponse.getRequestId());
        return "<p>Successfully registered device:</p><pre>" +
                registration +
                "</pre>" + NAVIGATION_MENU;
    }

    @Path("startAuthentication")
    @GET
    public View startAuthentication(@QueryParam("username") String username) throws U2fException {
        AuthenticateRequestData authenticateRequestData = u2f.startAuthentication(SERVER_ADDRESS, getRegistrations(username));
        storage.put(authenticateRequestData.getRequestId(), authenticateRequestData.toJson());
        return new AuthenticationView(authenticateRequestData.toJson(), username);
    }

    @Path("finishAuthentication")
    @POST
    public String finishAuthentication(@FormParam("tokenResponse") String response,
                                       @FormParam("username") String username) throws U2fException {
        AuthenticateResponse authenticateResponse = AuthenticateResponse.fromJson(response);
        AuthenticateRequestData authenticateRequest = AuthenticateRequestData.fromJson(storage.get(authenticateResponse.getRequestId()));
        storage.remove(authenticateResponse.getRequestId());
        u2f.finishAuthentication(authenticateRequest, authenticateResponse, getRegistrations(username));
        return "<p>Successfully authenticated!<p>" + NAVIGATION_MENU;
    }

    @Path("loginIndex")
    @GET
    public String loginIndex() throws Exception {
        URL index = Resource.class.getResource("loginIndex.html");
        return Files.toString(new File(index.toURI()), Charsets.UTF_8);
    }

    @Path("registerIndex")
    @GET
    public String registerIndex() throws Exception {
        URL defaultImage = Resource.class.getResource("registerIndex.html");
        return Files.toString(new File(defaultImage.toURI()), Charsets.UTF_8);
    }
}
