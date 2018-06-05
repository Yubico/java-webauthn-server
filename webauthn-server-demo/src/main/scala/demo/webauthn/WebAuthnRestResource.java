package demo.webauthn;

import javax.ws.rs.DELETE;
import javax.ws.rs.DefaultValue;
import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.ResponseBuilder;
import javax.ws.rs.core.Response.Status;
import javax.ws.rs.core.UriInfo;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.yubico.webauthn.VersionInfo$;
import com.yubico.webauthn.data.AssertionRequest;
import demo.webauthn.data.RegistrationRequest;
import demo.webauthn.json.ScalaJackson;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import scala.util.Either;
import scala.util.Left;
import scala.util.Right;

@Path("/v1")
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
        public final Info info = new Info();
        private IndexResponse() throws MalformedURLException {
        }
    }
    private final class Index {
        public final URL addCredential;
        public final URL authenticate;
        public final URL deleteAccount;
        public final URL deregister;
        public final URL register;


        public Index() throws MalformedURLException {
            addCredential = uriInfo.getAbsolutePathBuilder().path("action").path("add-credential").build().toURL();
            authenticate = uriInfo.getAbsolutePathBuilder().path("authenticate").build().toURL();
            deleteAccount = uriInfo.getAbsolutePathBuilder().path("delete-account").build().toURL();
            deregister = uriInfo.getAbsolutePathBuilder().path("action").path("deregister").build().toURL();
            register = uriInfo.getAbsolutePathBuilder().path("register").build().toURL();
        }
    }
    private final class Info {
        public final URL version;

        public Info() throws MalformedURLException {
            version = uriInfo.getAbsolutePathBuilder().path("version").build().toURL();
        }

    }

    @GET
    public Response index() throws IOException {
        return Response.ok(jsonMapper.writeValueAsString(new IndexResponse())).build();
    }

    private static final class VersionResponse {
        public final VersionInfo$ version = VersionInfo$.MODULE$;
    }
    @GET
    @Path("version")
    public Response version() throws JsonProcessingException {
        return Response.ok(jsonMapper.writeValueAsString(new VersionResponse())).build();
    }


    private final class StartRegistrationResponse {
        public final boolean success = true;
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
    public Response startRegistration(
        @FormParam("username") String username,
        @FormParam("displayName") String displayName,
        @FormParam("credentialNickname") String credentialNickname,
        @FormParam("requireResidentKey") @DefaultValue("false") boolean requireResidentKey
    ) throws MalformedURLException {
        logger.trace("startRegistration username: {}, displayName: {}, credentialNickname: {}, requireResidentKey: {}", username, displayName, credentialNickname, requireResidentKey);
        Either<String, RegistrationRequest> result = server.startRegistration(
            username,
            displayName,
            credentialNickname,
            requireResidentKey
        );

        if (result.isRight()) {
            return startResponse("startRegistration", new StartRegistrationResponse(result.right().get()));
        } else {
            return messagesJson(
                Response.status(Status.BAD_REQUEST),
                result.left().get()
            );
        }
    }

    @Path("register/finish")
    @POST
    public Response finishRegistration(String responseJson) {
        logger.trace("finishRegistration responseJson: {}", responseJson);
        Either<List<String>, WebAuthnServer.SuccessfulRegistrationResult> result = server.finishRegistration(responseJson);
        return finishResponse(
            result,
            "Attestation verification failed; further error message(s) were unfortunately lost to an internal server error.",
            "finishRegistration",
            responseJson
        );
    }

    private final class StartAuthenticationResponse {
        public final boolean success = true;
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
    public Response startAuthentication(@FormParam("username") String username) throws MalformedURLException {
        logger.trace("startAuthentication username: {}", username);
        Either<List<String>, AssertionRequest> request = server.startAuthentication(Optional.ofNullable(username));
        if (request.isRight()) {
            return startResponse("startAuthentication", new StartAuthenticationResponse(request.right().get()));
        } else {
            return messagesJson(Response.status(Status.BAD_REQUEST), request.left().get());
        }
    }

    @Path("authenticate/finish")
    @POST
    public Response finishAuthentication(String responseJson) {
        logger.trace("finishAuthentication responseJson: {}", responseJson);

        Either<List<String>, WebAuthnServer.SuccessfulAuthenticationResult> result = server.finishAuthentication(responseJson);

        return finishResponse(
            result,
            "Authentication verification failed; further error message(s) were unfortunately lost to an internal server error.",
            "finishAuthentication",
            responseJson
        );
    }

    @Path("action/{action}/finish")
    @POST
    public Response finishAuthenticatedAction(@PathParam("action") String action, String responseJson) {
        logger.trace("finishAuthenticatedAction: {}, responseJson: {}", action, responseJson);
        Either<List<String>, ?> mappedResult = server.finishAuthenticatedAction(responseJson);

        return finishResponse(
            mappedResult,
            "Action succeeded; further error message(s) were unfortunately lost to an internal server error.",
            "finishAuthenticatedAction",
            responseJson
        );
    }

    private final class StartAuthenticatedActionResponse {
        public final boolean success = true;
        public final AssertionRequest request;
        public final StartAuthenticatedActionActions actions = new StartAuthenticatedActionActions();
        private StartAuthenticatedActionResponse(AssertionRequest request) throws MalformedURLException {
            this.request = request;
        }
    }
    private final class StartAuthenticatedActionActions {
        public final URL finish = uriInfo.getAbsolutePathBuilder().path("finish").build().toURL();
        private StartAuthenticatedActionActions() throws MalformedURLException {
        }
    }

    @Path("action/add-credential")
    @POST
    public Response addCredential(
        @FormParam("username") String username,
        @FormParam("credentialNickname") String credentialNickname,
        @FormParam("requireResidentKey") @DefaultValue("false") boolean requireResidentKey
    ) throws MalformedURLException {
        logger.trace("addCredential username: {}, credentialNickname: {}, requireResidentKey: {}", username, credentialNickname, requireResidentKey);

        Either<List<String>, AssertionRequest> result = server.startAddCredential(username, credentialNickname, requireResidentKey, (RegistrationRequest request) -> {
            try {
                return Right.apply(new StartRegistrationResponse(request));
            } catch (MalformedURLException e) {
                logger.error("Failed to construct registration response", e);
                return Left.apply(Arrays.asList("Failed to construct response. This is probably a bug in the server."));
            }
        });

        if (result.isRight()) {
            return startResponse("addCredential", new StartAuthenticatedActionResponse(result.right().get()));
        } else {
            return messagesJson(
                Response.status(Status.BAD_REQUEST),
                result.left().get()
            );
        }
    }

    @Path("action/add-credential/finish/finish")
    @POST
    public Response finishAddCredential(String responseJson) {
        return finishRegistration(responseJson);
    }

    @Path("action/deregister")
    @POST
    public Response deregisterCredential(@FormParam("username") String username, @FormParam("credentialId") String credentialId) throws MalformedURLException {
        logger.trace("deregisterCredential username: {}, credentialId: {}", username, credentialId);

        Either<List<String>, AssertionRequest> result = server.deregisterCredential(username, credentialId, (credentialRegistration -> {
            try {
                return ((ObjectNode) jsonFactory.objectNode()
                        .set("success", jsonFactory.booleanNode(true)))
                        .set("droppedRegistration", jsonMapper.readTree(jsonMapper.writeValueAsString(credentialRegistration)))
                ;
            } catch (IOException e) {
                logger.error("Failed to write response as JSON", e);
                throw new RuntimeException(e);
            }
        }));

        if (result.isRight()) {
            return startResponse("deregisterCredential", new StartAuthenticatedActionResponse(result.right().get()));
        } else {
            return messagesJson(
                Response.status(Status.BAD_REQUEST),
                result.left().get()
            );
        }
    }

    @Path("delete-account")
    @DELETE
    public Response deleteAccount(@FormParam("username") String username) {
        logger.trace("deleteAccount username: {}", username);

        Either<List<String>, JsonNode> result = server.deleteAccount(username, () ->
            ((ObjectNode) jsonFactory.objectNode()
                .set("success", jsonFactory.booleanNode(true)))
                .set("deletedAccount", jsonFactory.textNode(username))
        );

        if (result.isRight()) {
            return Response.ok(result.right().get().toString()).build();
        } else {
            return messagesJson(
                Response.status(Status.BAD_REQUEST),
                result.left().get()
            );
        }
    }

    private Response startResponse(String operationName, Object request) {
        try {
            String json = jsonMapper.writeValueAsString(request);
            logger.debug("{} JSON response: {}", operationName, json);
            return Response.ok(json).build();
        } catch (IOException e) {
            return jsonFail();
        }
    }

    private Response finishResponse(Either<List<String>, ?> result, String jsonFailMessage, String methodName, String responseJson) {
        if (result.isRight()) {
            try {
                return Response.ok(
                    jsonMapper.writeValueAsString(result.right().get())
                ).build();
            } catch (JsonProcessingException e) {
                logger.error("Failed to encode response as JSON: {}", result.right().get(), e);
                return messagesJson(
                    Response.ok(),
                    jsonFailMessage
                );
            }
        } else {
            logger.debug("fail {} responseJson: {}", methodName, responseJson);
            return messagesJson(
                Response.status(Status.BAD_REQUEST),
                result.left().get()
            );
        }
    }

    private Response jsonFail() {
        return Response.status(Status.INTERNAL_SERVER_ERROR)
            .entity("{\"messages\":[\"Failed to encode response as JSON\"]}")
            .build();
    }

    private Response messagesJson(ResponseBuilder response, String message) {
        return messagesJson(response, Arrays.asList(message));
    }

    private Response messagesJson(ResponseBuilder response, List<String> messages) {
        logger.debug("Encoding messages as JSON: {}", messages);
        try {
            return response.entity(
                jsonMapper.writeValueAsString(
                    jsonFactory.objectNode()
                        .set("messages", jsonFactory.arrayNode()
                            .addAll(messages.stream().map(jsonFactory::textNode).collect(Collectors.toList()))
                        )
                )
            ).build();
        } catch (JsonProcessingException e) {
            logger.error("Failed to encode messages as JSON: {}", messages, e);
            return jsonFail();
        }
    }

}
