package demo;

import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Response;

public class U2fDemoException extends WebApplicationException {
    public U2fDemoException() {
        super(Response.status(Response.Status.NOT_FOUND).build());
    }

    public U2fDemoException(String message) {
        super(Response.status(Response.Status.NOT_FOUND).
                entity(message).type("text/plain").build());
    }
}
