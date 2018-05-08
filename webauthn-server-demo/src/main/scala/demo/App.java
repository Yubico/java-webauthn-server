package demo;

import javax.ws.rs.core.Application;

import demo.webauthn.WebAuthnRestResource;
import java.net.MalformedURLException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

public class App extends Application {
    @Override

    public Set<Class<?>> getClasses() {
        return new HashSet<>(Arrays.asList(
            CorsFilter.class
        ));
    }

    @Override
    public Set<Object> getSingletons() {
        return new HashSet<>(Arrays.asList(
            new WebAuthnRestResource()
        ));
    }

}
