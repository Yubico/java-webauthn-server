package demo;

import com.sun.jersey.api.Responses;

import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Response;

public class U2fDemoException extends WebApplicationException {
    public U2fDemoException() {
        super(Responses.notFound().build());
    }

    public U2fDemoException(String message) {
        super(Response.status(Responses.NOT_FOUND).
                entity(message).type("text/plain").build());
    }
}
