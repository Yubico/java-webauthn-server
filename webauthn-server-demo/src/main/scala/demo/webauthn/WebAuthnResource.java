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
import demo.webauthn.view.AssertionView;
import demo.webauthn.view.FinishAssertionView;
import demo.webauthn.view.FinishRegistrationView;
import demo.webauthn.view.MessageView;
import demo.webauthn.view.RegistrationView;
import io.dropwizard.views.View;
import java.security.cert.CertificateException;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import scala.util.Either;

@Path("/webauthn")
@Produces(MediaType.TEXT_HTML)
public class WebAuthnResource {

    private static final Logger logger = LoggerFactory.getLogger(WebAuthnResource.class);

    private final WebAuthnServer server;
    private final ObjectMapper jsonMapper = new ScalaJackson().get();

    public WebAuthnResource() {
        this(new WebAuthnServer());
    }

    public WebAuthnResource(WebAuthnServer server) {
        this.server = server;
    }

    @Path("startRegistration")
    @GET
    public View startRegistration(@QueryParam("username") String username, @QueryParam("credentialNickname") String credentialNickname) throws JsonProcessingException {
        logger.info("startRegistration username: {}, credentialNickname: {}", username, credentialNickname);
        RegistrationRequest request = server.startRegistration(username, credentialNickname);
        return new RegistrationView(username, request.getRequestId(), jsonMapper.writeValueAsString(request));
    }

    @Path("finishRegistration")
    @POST
    public View finishRegistration(@FormParam("response") String responseJson) throws CertificateException, NoSuchFieldException, JsonProcessingException {
        logger.info("finishRegistration responseJson: {}", responseJson);
        Either<List<String>, WebAuthnServer.SuccessfulRegistrationResult> result = server.finishRegistration(responseJson);

        if (result.isRight()) {
            return new FinishRegistrationView(
                result.right().get().getRegistration(),
                jsonMapper.writeValueAsString(result.right().get().getRequest()),
                result.right().get().getResponse(),
                jsonMapper.writeValueAsString(result.right().get().getResponse())
            );
        } else {
            logger.info("fail finishRegistration responseJson: {}", responseJson);
            return new MessageView(result.left().get());
        }
    }

    @Path("startAuthentication")
    @GET
    public View startAuthentication(@QueryParam("username") String username) throws JsonProcessingException {
        logger.info("startAuthentication username: {}", username);
        AssertionRequest request = server.startAuthentication(username);
        return new AssertionView(username, request.getRequestId(), jsonMapper.writeValueAsString(request));
    }

    @Path("finishAuthentication")
    @POST
    public View finishAuthentication(@FormParam("response") String responseJson) throws JsonProcessingException {
        logger.info("finishAuthentication responseJson: {}", responseJson);

        Either<List<String>, WebAuthnServer.SuccessfulAuthenticationResult> result = server.finishAuthentication(responseJson);

        if (result.isRight()) {
            return new FinishAssertionView(
                jsonMapper.writeValueAsString(result.right().get().getRequest()),
                jsonMapper.writeValueAsString(result.right().get().getResponse()),
                jsonMapper.writeValueAsString(result.right().get().getRegistrations()),
                result.right().get().getRegistrations()
            );
        } else {
            return new MessageView(result.left().get());
        }
    }

}
