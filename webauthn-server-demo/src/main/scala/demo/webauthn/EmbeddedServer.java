package demo.webauthn;

import javax.ws.rs.core.UriBuilder;

import demo.App;
import java.net.URI;
import org.eclipse.jetty.server.Connector;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.glassfish.jersey.jetty.JettyHttpContainerFactory;
import org.glassfish.jersey.server.ResourceConfig;

public class EmbeddedServer {

    public static void main(String[] args) throws Exception {
        final int port = Config.getPort();

        URI baseUri = UriBuilder.fromUri("http://localhost").port(port).build();

        App app = new App();

        ResourceConfig config = new ResourceConfig();
        config.registerClasses(app.getClasses());
        config.registerInstances(app.getSingletons());

        Server server = JettyHttpContainerFactory.createServer(baseUri, config, false);
        ServerConnector connector = new ServerConnector(server);
        connector.setPort(port);
        connector.setHost("127.0.0.1");
        server.setConnectors(new Connector[] { connector });
        server.start();
    }

}
