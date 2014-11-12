package demo;

import com.google.common.base.Charsets;
import com.google.common.io.Files;
import com.yubico.u2f.data.DeviceRegistration;
import com.yubico.u2f.data.messages.AuthenticateRequest;
import com.yubico.u2f.data.messages.RegisterRequest;
import com.yubico.u2f.exceptions.U2fException;
import com.yubico.u2f.U2F;
import com.yubico.u2f.data.messages.AuthenticateResponse;
import com.yubico.u2f.data.messages.RegisterResponse;
import demo.view.AuthenticationView;
import demo.view.RegistrationView;
import io.dropwizard.views.View;

import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import java.io.File;
import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;

@Path("/")
@Produces(MediaType.TEXT_HTML)
public class Resource {

  public static final String SERVER_ADDRESS = "http://example.com:8080";

  // In production, you want to store DeviceRegistrations persistently (e.g. in a database).
  private final Map<String, String> storage = new HashMap<String, String>();
  private final U2F u2f = new U2F();

  @Path("startRegistration")
  @GET
  public View startRegistration() {
    RegisterRequest registerRequest = u2f.startRegistration(SERVER_ADDRESS);
    storage.put(registerRequest.getChallenge(), registerRequest.toJson());
    return new RegistrationView(registerRequest.toJson());
  }

  @Path("finishRegistration")
  @POST
  public String finishRegistration(@FormParam("tokenResponse") String response, @FormParam("username") String username)
          throws U2fException {
    RegisterResponse registerResponse = RegisterResponse.fromJson(response);
    String challenge = registerResponse.getClientData().getChallenge();
    RegisterRequest registerRequest = RegisterRequest.fromJson(storage.get(challenge));
    DeviceRegistration registration = u2f.finishRegistration(registerRequest, registerResponse);
    storage.put(username, registration.toJson());
    storage.remove(challenge);
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

  @Path("startAuthentication")
  @GET
  public View startAuthentication(@QueryParam("username") String username) {
    DeviceRegistration registration = DeviceRegistration.fromJson(storage.get(username));
    if(registration == null) {
      throw new U2fDemoException("No device registered for that username");
    }
    AuthenticateRequest authenticateRequest = u2f.startAuthentication(SERVER_ADDRESS, registration);
    storage.put(authenticateRequest.getChallenge(), authenticateRequest.toJson());
    return new AuthenticationView(authenticateRequest.toJson(), username);
  }

  @Path("finishAuthentication")
  @POST
  public String finishAuthentication(@FormParam("tokenResponse") String response,
                                     @FormParam("username") String username) throws U2fException {
    DeviceRegistration registration = DeviceRegistration.fromJson(storage.get(username));
    AuthenticateResponse authenticateResponse = AuthenticateResponse.fromJson(response);
    String challenge = authenticateResponse.getClientData().getChallenge();
    AuthenticateRequest authenticateRequest = AuthenticateRequest.fromJson(storage.get(challenge));
    storage.remove(challenge);
    u2f.finishAuthentication(authenticateRequest, authenticateResponse, registration);
    return "Successfully authenticated.";
  }
}
