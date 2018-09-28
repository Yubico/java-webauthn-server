package demo;

import javax.ws.rs.core.Application;

import com.yubico.webauthn.extension.appid.InvalidAppIdException;
import demo.webauthn.WebAuthnRestResource;
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
        try {
            return new HashSet<>(Arrays.asList(
                new WebAuthnRestResource()
            ));
        } catch (InvalidAppIdException e) {
            throw new RuntimeException(e);
        }
    }

}
