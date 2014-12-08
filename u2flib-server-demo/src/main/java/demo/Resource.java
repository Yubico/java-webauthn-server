package demo;

import com.google.common.collect.ArrayListMultimap;
import com.google.common.collect.Multimap;
import com.yubico.u2f.U2F;
import com.yubico.u2f.U2fPrimitives;
import com.yubico.u2f.data.DeviceRegistration;
import com.yubico.u2f.data.messages.AuthenticateRequestData;
import com.yubico.u2f.data.messages.AuthenticateResponse;
import com.yubico.u2f.data.messages.RegisterRequestData;
import com.yubico.u2f.data.messages.RegisterResponse;
import com.yubico.u2f.exceptions.U2fException;
import demo.view.AuthenticationView;
import demo.view.RegistrationView;
import io.dropwizard.views.View;

import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.*;

@Path("/")
@Produces(MediaType.TEXT_HTML)
public class Resource {

    public static final String SERVER_ADDRESS = "http://localhost:8080";
    public static final String NAVIGATION_MENU = "<h2>Navigation</h2><ul><li><a href='registerIndex'>Register</a></li><li><a href='loginIndex'>Login</a></li></ul>.";

    private final Map<String, String> requestStorage = new HashMap<String, String>();
    private final Multimap<String, String> userStorage = ArrayListMultimap.create();
    private final U2F u2f = new U2F();

    @Path("startRegistration")
    @GET
    public View startRegistration(@QueryParam("username") String username) {
        RegisterRequestData registerRequestData = u2f.startRegistration(SERVER_ADDRESS, getRegistrations(username));
        requestStorage.put(registerRequestData.getRequestId(), registerRequestData.toJson());
        return new RegistrationView(registerRequestData.toJson(), username);
    }

    @Path("finishRegistration")
    @POST
    public String finishRegistration(@FormParam("tokenResponse") String response, @FormParam("username") String username)
            throws U2fException {
        RegisterResponse registerResponse = RegisterResponse.fromJson(response);
        RegisterRequestData registerRequestData = RegisterRequestData.fromJson(requestStorage.remove(registerResponse.getRequestId()));
        DeviceRegistration registration = u2f.finishRegistration(registerRequestData, registerResponse);
        addRegistration(username, registration);
        return "<p>Successfully registered device:</p><pre>" +
                registration +
                "</pre>" + NAVIGATION_MENU;
    }

    @Path("startAuthentication")
    @GET
    public View startAuthentication(@QueryParam("username") String username) throws U2fException {
        AuthenticateRequestData authenticateRequestData = u2f.startAuthentication(SERVER_ADDRESS, getRegistrations(username));
        requestStorage.put(authenticateRequestData.getRequestId(), authenticateRequestData.toJson());
        return new AuthenticationView(authenticateRequestData.toJson(), username);
    }

    @Path("finishAuthentication")
    @POST
    public String finishAuthentication(@FormParam("tokenResponse") String response,
                                       @FormParam("username") String username) throws U2fException {
        AuthenticateResponse authenticateResponse = AuthenticateResponse.fromJson(response);
        AuthenticateRequestData authenticateRequest = AuthenticateRequestData.fromJson(requestStorage.remove(authenticateResponse.getRequestId()));
        u2f.finishAuthentication(authenticateRequest, authenticateResponse, getRegistrations(username));
        return "<p>Successfully authenticated!<p>" + NAVIGATION_MENU;
    }

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

    @Path("loginIndex")
    @GET
    public Response loginIndex() throws Exception {
      return Response.ok()
              .entity(Resource.class.getResourceAsStream("loginIndex.html"))
              .build();
    }

    @Path("registerIndex")
    @GET
    public Response registerIndex() throws Exception {
        return Response.ok()
                .entity(Resource.class.getResourceAsStream("registerIndex.html"))
                .build();
    }
}
