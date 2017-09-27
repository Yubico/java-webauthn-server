package demo.webauthn;

import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;
import javax.ws.rs.core.UriInfo;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.List;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import scala.util.Either;

@Path("/webauthn/rest")
@Produces(MediaType.APPLICATION_JSON)
public class WebAuthnRestResource {
    private static final Logger logger = LoggerFactory.getLogger(WebAuthnRestResource.class);

    private final WebAuthnServer server;
    private final ObjectMapper jsonMapper = new ScalaJackson().get();
    private final JsonNodeFactory jsonFactory = JsonNodeFactory.instance;

    public WebAuthnRestResource() {
        this(new WebAuthnServer());
    }

    public WebAuthnRestResource(WebAuthnServer server) {
        this.server = server;
    }

    @Context
    private UriInfo uriInfo;

    private final class IndexResponse {
        public final Index actions = new Index();
        private IndexResponse() throws NoSuchMethodException, MalformedURLException {
        }
    }
    private final class Index {
        public final URL register;
        public final URL authenticate;
        public final URL deregister;

        public Index() throws NoSuchMethodException, MalformedURLException {
            register = uriInfo.getAbsolutePathBuilder().path("register").build().toURL();
            authenticate = uriInfo.getAbsolutePathBuilder().path("authenticate").build().toURL();
            deregister = uriInfo.getAbsolutePathBuilder().path("deregisterCredential").build().toURL();
        }
    }

    @Path("/")
    @GET
    public Response index() throws NoSuchMethodException, IOException {
        return Response.ok(jsonMapper.writeValueAsString(new IndexResponse())).build();
    }


    private final class StartRegistrationResponse {
        public final RegistrationRequest request;
        public final StartRegistrationActions actions = new StartRegistrationActions();
        private StartRegistrationResponse(RegistrationRequest request) throws MalformedURLException {
            this.request = request;
        }
    }
    private final class StartRegistrationActions {
        public final URL finish = uriInfo.getAbsolutePathBuilder().path("finish").build().toURL();
        private StartRegistrationActions() throws MalformedURLException {
        }
    }

    @Path("register")
    @POST
    public Response startRegistration(@QueryParam("username") String username, @QueryParam("credentialNickname") String credentialNickname) throws MalformedURLException {
        logger.info("startRegistration username: {}, credentialNickname: {}", username, credentialNickname);
        RegistrationRequest request = server.startRegistration(username, credentialNickname);
        return startResponse(new StartRegistrationResponse(request));
    }

    @Path("register/finish")
    @POST
    public Response finishRegistration(String responseJson) {
        logger.info("finishRegistration responseJson: {}", responseJson);
        Either<List<String>, WebAuthnServer.SuccessfulRegistrationResult> result = server.finishRegistration(responseJson);
        return finishResponse(
            result,
            "Attestation verification failed; further error message(s) were unfortunately lost to an internal server error.",
            "finishRegistration",
            responseJson
        );
    }

    private final class StartAuthenticationResponse {
        public final AssertionRequest request;
        public final StartAuthenticationActions actions = new StartAuthenticationActions();
        private StartAuthenticationResponse(AssertionRequest request) throws MalformedURLException {
            this.request = request;
        }
    }
    private final class StartAuthenticationActions {
        public final URL finish = uriInfo.getAbsolutePathBuilder().path("finish").build().toURL();
        private StartAuthenticationActions() throws MalformedURLException {
        }
    }
    @Path("authenticate")
    @POST
    public Response startAuthentication(@QueryParam("username") String username) throws JsonProcessingException, MalformedURLException {
        logger.info("startAuthentication username: {}", username);
        AssertionRequest request = server.startAuthentication(username);
        return startResponse(new StartAuthenticationResponse(request));
    }

    @Path("authenticate/finish")
    @POST
    public Response finishAuthentication(String responseJson) {
        logger.info("finishAuthentication responseJson: {}", responseJson);

        Either<List<String>, WebAuthnServer.SuccessfulAuthenticationResult> result = server.finishAuthentication(responseJson);

        return finishResponse(
            result,
            "Authentication verification failed; further error message(s) were unfortunately lost to an internal server error.",
            "finishAuthentication",
            responseJson
        );
    }

    @Path("deregister")
    @POST
    public Response deregisterCredential(@QueryParam("username") String username, @QueryParam("credentialId") String credentialId) {
        logger.info("deregisterCredential username: {}, credentialId: {}", username, credentialId);

        Either<List<String>, CredentialRegistration> result = server.deregisterCredential(username, credentialId);

        if (result.isRight()) {
            try {
                return Response.ok(
                    jsonMapper.writeValueAsString(
                        ((ObjectNode) jsonFactory.objectNode()
                            .set("success", jsonFactory.booleanNode(true)))
                            .set("droppedRegistration", jsonMapper.readTree(jsonMapper.writeValueAsString(result.right().get())))
                    )
                ).build();
            } catch (IOException e) {
                return jsonFail();
            }
        } else {
            return Response.status(Status.NOT_FOUND)
                .entity("{\"messages\":[\"No such credential registration found.\"]}")
                .build();
        }
    }

    private Response startResponse(Object request) {
        try {
            return Response.ok(jsonMapper.writeValueAsString(request)).build();
        } catch (IOException e) {
            return jsonFail();
        }
    }

    private Response finishResponse(Either<List<String>, ?> result, String failFailMessage, String methodName, String responseJson) {
        if (result.isRight()) {
            try {
                return Response.ok(
                    jsonMapper.writeValueAsString(result.right().get())
                ).build();
            } catch (JsonProcessingException e) {
                return Response.status(Status.INTERNAL_SERVER_ERROR)
                    .entity("{\"messages\";[\"Failed to encode response as JSON\"]}")
                    .build();
            }
        } else {
            logger.info("fail {} responseJson: {}", methodName, responseJson);
            try {
                return Response.status(Status.BAD_REQUEST)
                    .entity(
                        jsonMapper.writeValueAsString(
                            jsonFactory.objectNode()
                                .set("messages", jsonFactory.arrayNode()
                                    .addAll(result.left().get().stream().map(jsonFactory::textNode).collect(Collectors.toList()))
                                )
                        )
                    )
                    .build();
            } catch (JsonProcessingException e) {
                return Response.status(Status.BAD_REQUEST)
                    .entity("{\"messages\":[\"" + failFailMessage + "\"]}")
                    .build();
            }
        }
    }

    private Response jsonFail() {
        return Response.status(Status.INTERNAL_SERVER_ERROR)
            .entity("{\"messages\";[\"Failed to encode response as JSON\"]}")
            .build();
    }

}
