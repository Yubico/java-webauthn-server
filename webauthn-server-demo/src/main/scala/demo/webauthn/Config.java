package demo.webauthn;

import com.yubico.webauthn.data.RelyingPartyIdentity;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Config {

    private static final Logger logger = LoggerFactory.getLogger(Config.class);

    private static final String DEFAULT_ORIGIN = "https://localhost:8443";
    private static final int DEFAULT_PORT = 8080;
    private static final RelyingPartyIdentity DEFAULT_RP_ID
        = new RelyingPartyIdentity("Yubico WebAuthn demo", "localhost", Optional.empty());

    private final List<String> origins;
    private final int port;
    private final RelyingPartyIdentity rpIdentity;

    private Config(List<String> origins, int port, RelyingPartyIdentity rpIdentity) {
        this.origins = Collections.unmodifiableList(origins);
        this.port = port;
        this.rpIdentity = rpIdentity;
    }

    private static Config instance;
    private static Config getInstance() {
        if (instance == null) {
            try {
                instance = new Config(computeOrigins(), computePort(), computeRpIdentity());
            } catch (MalformedURLException e) {
                throw new RuntimeException(e);
            }
        }
        return instance;
    }

    public static List<String> getOrigins() {
        return getInstance().origins;
    }

    public static int getPort() {
        return getInstance().port;
    }

    public static RelyingPartyIdentity getRpIdentity() {
        return getInstance().rpIdentity;
    }

    private static List<String> computeOrigins() {
        final String origins = System.getenv("YUBICO_WEBAUTHN_ALLOWED_ORIGINS");

        logger.debug("YUBICO_WEBAUTHN_ALLOWED_ORIGINS: {}", origins);

        final List<String> result;

        if (origins == null) {
            result = Arrays.asList(DEFAULT_ORIGIN);
        } else {
            result = Arrays.asList(origins.split(","));
        }

        logger.info("Origins: {}", result);

        return result;
    }

    private static int computePort() {
        final String port = System.getenv("YUBICO_WEBAUTHN_PORT");

        if (port == null) {
            return DEFAULT_PORT;
        } else {
            return Integer.parseInt(port);
        }
    }

    private static RelyingPartyIdentity computeRpIdentity() throws MalformedURLException {
        final String name = System.getenv("YUBICO_WEBAUTHN_RP_NAME");
        final String id = System.getenv("YUBICO_WEBAUTHN_RP_ID");
        final String icon = System.getenv("YUBICO_WEBAUTHN_RP_ICON");

        logger.debug("RP name: {}", name);
        logger.debug("RP ID: {}", id);
        logger.debug("RP icon: {}", icon);

        final RelyingPartyIdentity result;

        if (name == null || id == null) {
            logger.debug("RP name or ID not given - using default.");
            result = DEFAULT_RP_ID;
        } else {
            Optional<URL> iconUrl = Optional.empty();
            if (icon != null) {
                try {
                    iconUrl = Optional.of(new URL(icon));
                } catch (MalformedURLException e) {
                    logger.error("Invalid icon URL: {}", icon, e);
                    throw e;
                }
            }
            result = new RelyingPartyIdentity(name, id, iconUrl);
        }

        logger.info("RP identity: {}", result);

        return result;
    }

}
