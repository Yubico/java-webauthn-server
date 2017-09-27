package demo;

import demo.webauthn.WebAuthnResource;
import demo.webauthn.WebAuthnRestResource;
import io.dropwizard.Application;
import io.dropwizard.assets.AssetsBundle;
import io.dropwizard.jersey.setup.JerseyEnvironment;
import io.dropwizard.setup.Bootstrap;
import io.dropwizard.setup.Environment;
import io.dropwizard.views.ViewBundle;

public class App extends Application<Config> {
    @Override
    public void initialize(Bootstrap<Config> bootstrap) {
        bootstrap.addBundle(new ViewBundle());
        bootstrap.addBundle(new AssetsBundle("/assets/", "/", "index.html"));
    }

    @Override
    public void run(Config config, Environment environment) throws Exception {
        JerseyEnvironment jersey = environment.jersey();
        jersey.setUrlPattern("/api/*");
        jersey.register(new WebAuthnResource());
        jersey.register(new WebAuthnRestResource());
    }

    public static void main(String... args) throws Exception {
        new App().run(args);
    }
}
