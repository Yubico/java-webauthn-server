// Copyright (c) 2018, Yubico AB
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

package demo.webauthn;

import demo.App;
import org.eclipse.jetty.http.HttpVersion;
import org.eclipse.jetty.server.Connector;
import org.eclipse.jetty.server.HttpConfiguration;
import org.eclipse.jetty.server.HttpConnectionFactory;
import org.eclipse.jetty.server.SecureRequestCustomizer;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.server.SslConnectionFactory;
import org.eclipse.jetty.servlet.DefaultServlet;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.glassfish.jersey.server.ResourceConfig;
import org.glassfish.jersey.servlet.ServletContainer;

/**
 * Standalone Java application launcher that runs the demo server with the API but no static
 * resources (i.e., no web GUI)
 */
public class EmbeddedServer {

  public static void main(String[] args) throws Exception {
    final int port = Config.getPort();

    App app = new App();

    ResourceConfig config = new ResourceConfig();
    config.registerClasses(app.getClasses());
    config.registerInstances(app.getSingletons());

    SslContextFactory ssl = new SslContextFactory("keystore.jks");
    ssl.setKeyStorePassword("p@ssw0rd");

    Server server = new Server();
    HttpConfiguration httpConfig = new HttpConfiguration();
    httpConfig.setSecureScheme("https");
    httpConfig.setSecurePort(port);
    HttpConfiguration httpsConfig = new HttpConfiguration(httpConfig);
    httpsConfig.addCustomizer(new SecureRequestCustomizer());

    ServerConnector connector =
        new ServerConnector(
            server,
            new SslConnectionFactory(ssl, HttpVersion.HTTP_1_1.asString()),
            new HttpConnectionFactory(httpsConfig));

    connector.setPort(port);
    connector.setHost("127.0.0.1");

    ServletHolder servlet = new ServletHolder(new ServletContainer(config));
    ServletContextHandler context = new ServletContextHandler(server, "/");
    context.addServlet(DefaultServlet.class, "/");
    context.setResourceBase("src/main/webapp");
    context.addServlet(servlet, "/api/*");

    server.setConnectors(new Connector[] {connector});
    server.start();
  }
}
