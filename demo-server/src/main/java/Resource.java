import com.google.common.collect.ImmutableSet;
import com.yubico.u2f.U2fException;
import com.yubico.u2f.server.U2F;
import com.yubico.u2f.server.data.Device;
import com.yubico.u2f.server.messages.RegistrationResponse;
import com.yubico.u2f.server.messages.StartedRegistration;
import redis.clients.jedis.Jedis;

import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import java.util.Set;

@Path("/")
public class Resource {

  static final Set<String> FACETS = ImmutableSet.of("http://example.com");
  public static final String APP_ID = "demo-app";
  Jedis storage = new Jedis("localhost");

  @Path("registration")
  @GET
  public String startRegistration() {
    StartedRegistration startedRegistration = U2F.startRegistration(APP_ID);

    storage.set(startedRegistration.getChallenge(), startedRegistration.toJson());

    return startedRegistration.toJson();
  }

  @Path("registration")
  @POST
  public String finishRegistration(String username, String response) throws U2fException {
    RegistrationResponse registrationResponse = RegistrationResponse.fromJson(response);

    String startedRegistration = storage.get(registrationResponse.getClientData().getChallenge());

    Device registeredDevice = U2F.finishRegistration(startedRegistration, response, FACETS);

    storage.lpush(username, registeredDevice.toJson());

    return "Successfully registered";
  }
}
