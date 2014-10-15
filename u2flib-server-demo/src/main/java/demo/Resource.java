package demo;

import com.google.common.base.Charsets;
import com.google.common.collect.ImmutableSet;
import com.google.common.io.Files;
import com.yubico.u2f.U2fException;
import com.yubico.u2f.server.U2F;
import com.yubico.u2f.server.data.Device;
import com.yubico.u2f.server.messages.AuthenticationResponse;
import com.yubico.u2f.server.messages.RegistrationResponse;
import com.yubico.u2f.server.messages.StartedAuthentication;
import com.yubico.u2f.server.messages.StartedRegistration;
import demo.view.AuthenticationView;
import demo.view.RegistrationView;
import io.dropwizard.views.View;
import redis.clients.jedis.Jedis;

import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import java.io.File;
import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.Set;

@Path("/")
@Produces(MediaType.TEXT_HTML)
public class Resource {

  static final Set<String> FACETS = ImmutableSet.of("http://example.com:8080");
  public static final String APP_ID = "http://example.com:8080";
  Jedis storage = new Jedis("localhost");

  @Path("startRegistration")
  @GET
  public View startRegistration() {
    StartedRegistration startedRegistration = U2F.startRegistration(APP_ID);
    storage.set(startedRegistration.getChallenge(), startedRegistration.toJson());
    return new RegistrationView(startedRegistration.toJson());
  }

  @Path("finishRegistration")
  @POST
  public String finishRegistration(@FormParam("tokenResponse") String response, @FormParam("username") String username)
          throws U2fException {
    RegistrationResponse registrationResponse = RegistrationResponse.fromJson(response);
    StartedRegistration startedRegistration = StartedRegistration.fromJson(
            storage.get(registrationResponse.getClientData().getChallenge())
    );
    Device registeredDevice = U2F.finishRegistration(startedRegistration, registrationResponse, FACETS);
    storage.set(username, registeredDevice.toJson());
    return "<p>Successfully registered device:</p><code>" +
            registeredDevice.toJson() +
            "</code><p>Now you might want to <a href='loginIndex'>login</a></p>.";
  }

  @Path("loginIndex")
  @GET
  public String loginIndex() throws IOException, URISyntaxException {
    URL defaultImage = Resource.class.getResource("loginIndex.html");
    return Files.toString(new File(defaultImage.toURI()), Charsets.UTF_8);
    //return Files.toString(new File("loginIndex.hmtl"), Charsets.UTF_8);
  }

  @Path("startAuthentication")
  @GET
  public View startAuthentication(@QueryParam("username") String username) {
    Device device = Device.fromJson(storage.get(username));
    if(device == null) {
      throw new U2fDemoException("No such user");
    }
    StartedAuthentication startedAuthentication = U2F.startAuthentication(APP_ID, device);
    storage.set(startedAuthentication.getChallenge(), startedAuthentication.toJson());
    return new AuthenticationView(startedAuthentication.toJson(), username);
  }

  @Path("finishAuthentication")
  @POST
  public String finishAuthentication(@FormParam("tokenResponse") String response,
                                     @FormParam("username") String username) throws U2fException {
    Device device = Device.fromJson(storage.get(username));
    AuthenticationResponse authenticationResponse = AuthenticationResponse.fromJson(response);
    StartedAuthentication startedAuthentication = StartedAuthentication.fromJson(
            storage.get(authenticationResponse.getClientData().getChallenge())
    );
    U2F.finishAuthentication(startedAuthentication, authenticationResponse, device, FACETS);
    return "Successfully authenticated.";
  }
}
