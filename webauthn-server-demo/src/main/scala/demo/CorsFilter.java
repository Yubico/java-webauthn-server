package demo;

import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerResponseContext;
import javax.ws.rs.container.ContainerResponseFilter;

import demo.webauthn.Config;
import java.io.IOException;

public class CorsFilter implements ContainerResponseFilter {

    @Override
    public void filter(ContainerRequestContext requestContext, ContainerResponseContext responseContext) throws IOException {
        String origin = requestContext.getHeaderString("origin");
        Config.getOrigins().stream()
            .filter(allowedOrigin -> allowedOrigin.equals(origin))
            .forEach(allowedOrigin ->
                responseContext.getHeaders().add("Access-Control-Allow-Origin", allowedOrigin)
            );
    }

}
