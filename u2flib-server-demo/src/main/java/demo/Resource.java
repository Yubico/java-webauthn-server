package demo;

import com.google.common.base.Charsets;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Lists;
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
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Path("/")
@Produces(MediaType.TEXT_HTML)
public class Resource {

    public static final String SERVER_ADDRESS = "http://example.com:8080";

    // In production, you want to store DeviceRegistrations persistently (e.g. in a database).
    private final Map<String, String> storage = new HashMap<String, String>();
    private final Map<String, List<String>> userStorage = new HashMap<String, List<String>>();
    private final U2F u2f = new U2F();

    private Iterable<DeviceRegistration> getRegistrations(String username) {
        List<String> serializedRegistrations = userStorage.get(username);
        if(serializedRegistrations == null) {
            return ImmutableList.of();
        }
        List<DeviceRegistration> registrations = new ArrayList<DeviceRegistration>();
        for(String serialized : serializedRegistrations) {
            registrations.add(DeviceRegistration.fromJson(serialized));
        }
        return registrations;
    }

    private void addRegistration(String username, DeviceRegistration registration) {
        List<String> serializedRegistrations = userStorage.get(username);
        if(serializedRegistrations == null) {
            userStorage.put(username, Lists.newArrayList(registration.toJson()));
        } else {
            serializedRegistrations.add(registration.toJson());
        }
    }

    @Path("startRegistration")
    @GET
    public View startRegistration(@QueryParam("username") String username) {
        RegisterRequestData registerRequestData = u2f.startRegistration(SERVER_ADDRESS, getRegistrations(username));
        storage.put(registerRequestData.getRequestId(), registerRequestData.toJson());
        return new RegistrationView(username, registerRequestData.toJson());
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
        return "<p>Successfully registered device:</p><code>" +
                registration +
                "</code><p>Now you might want to <a href='loginIndex'>login</a></p>.";
    }

    @Path("loginIndex")
    @GET
    public String loginIndex() throws IOException, URISyntaxException {
        URL defaultImage = Resource.class.getResource("loginIndex.html");
        return Files.toString(new File(defaultImage.toURI()), Charsets.UTF_8);
    }

    @Path("registerIndex")
    @GET
    public String registerIndex() throws IOException, URISyntaxException {
        URL defaultImage = Resource.class.getResource("registerIndex.html");
        return Files.toString(new File(defaultImage.toURI()), Charsets.UTF_8);
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
        return "Successfully authenticated.";
    }
}
