package demo;

import com.google.common.base.Charsets;
import com.google.common.collect.ImmutableSet;
import com.google.common.io.Files;
import com.yubico.u2f.exceptions.U2fException;
import com.yubico.u2f.U2F;
import com.yubico.u2f.data.Device;
import com.yubico.u2f.data.messages.AuthenticateResponse;
import com.yubico.u2f.data.messages.RegisterResponse;
import com.yubico.u2f.data.messages.StartedAuthentication;
import com.yubico.u2f.data.messages.StartedRegistration;
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
import java.util.Set;

@Path("/")
@Produces(MediaType.TEXT_HTML)
public class Resource {

  public static final String SERVER_ADDRESS = "http://example.com:8080";
  public static final Set<String> FACETS = ImmutableSet.of(SERVER_ADDRESS);

  // In production, you want to store Devices persistently (e.g. in a database).
  private final Map<String, String> storage = new HashMap<String, String>();

  @Path("startRegistration")
  @GET
  public View startRegistration() {
    StartedRegistration startedRegistration = U2F.startRegistration(SERVER_ADDRESS);
    storage.put(startedRegistration.getChallenge(), startedRegistration.toJson());
    return new RegistrationView(startedRegistration.toJson());
  }

  @Path("finishRegistration")
  @POST
  public String finishRegistration(@FormParam("tokenResponse") String response, @FormParam("username") String username)
          throws U2fException {
    RegisterResponse registerResponse = RegisterResponse.fromJson(response);
    String challenge = registerResponse.getClientData().getChallenge();
    StartedRegistration startedRegistration = StartedRegistration.fromJson(storage.get(challenge));
    Device registeredDevice = U2F.finishRegistration(startedRegistration, registerResponse, FACETS);
    storage.put(username, registeredDevice.toJson());
    storage.remove(challenge);
    return "<p>Successfully registered device:</p><code>" +
            registeredDevice +
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
    Device device = Device.fromJson(storage.get(username));
    if(device == null) {
      throw new U2fDemoException("No such user");
    }
    StartedAuthentication startedAuthentication = U2F.startAuthentication(SERVER_ADDRESS, device);
    storage.put(startedAuthentication.getChallenge(), startedAuthentication.toJson());
    return new AuthenticationView(startedAuthentication.toJson(), username);
  }

  @Path("finishAuthentication")
  @POST
  public String finishAuthentication(@FormParam("tokenResponse") String response,
                                     @FormParam("username") String username) throws U2fException {
    Device device = Device.fromJson(storage.get(username));
    AuthenticateResponse authenticateResponse = AuthenticateResponse.fromJson(response);
    String challenge = authenticateResponse.getClientData().getChallenge();
    StartedAuthentication startedAuthentication = StartedAuthentication.fromJson(storage.get(challenge));
    storage.remove(challenge);
    U2F.finishAuthentication(startedAuthentication, authenticateResponse, device, FACETS);
    return "Successfully authenticated.";
  }
}
