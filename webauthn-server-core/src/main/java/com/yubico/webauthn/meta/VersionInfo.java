package com.yubico.webauthn.meta;

import com.yubico.util.ExceptionUtil;
import com.yubico.webauthn.DocumentStatus;
import java.io.IOException;
import java.net.URL;
import java.time.LocalDate;
import java.util.Enumeration;
import java.util.Optional;
import java.util.jar.Manifest;
import lombok.extern.slf4j.Slf4j;


/**
 * Contains version information for the com.yubico.webauthn package.
 *
 * @see [[Specification]]
 */
@Slf4j
public class VersionInfo {

    private static VersionInfo instance;

    public static VersionInfo getInstance() {
        if (instance == null) {
            try {
                instance = new VersionInfo();
            } catch (IOException e) {
                throw ExceptionUtil.wrapAndLog(log, "Failed to create VersionInfo", e);
            }
        }

        return instance;
    }

    /**
     * Represents the specification this implementation is based on
     */
    private final Specification specification = Specification.builder()
        .url(new URL("https://www.w3.org/TR/2018/CR-webauthn-20180320/"))
        .latestVersionUrl(new URL("https://www.w3.org/TR/webauthn/"))
        .status(DocumentStatus.CANDIDATE_RECOMMENDATION)
        .releaseDate(LocalDate.parse("2018-03-20"))
        .build();

    /**
     * Represents the specification this implementation is based on
     */
    private final Implementation implementation = new Implementation(
        findImplementationVersionInManifest(),
        new URL("https://github.com/Yubico/java-webauthn-server")
    );

    public VersionInfo() throws IOException {
    }

    private Optional<String> findImplementationVersionInManifest() throws IOException {
        final Enumeration<URL> resources = getClass().getClassLoader().getResources("META-INF/MANIFEST.MF");

        while (resources.hasMoreElements()) {
            final URL resource = resources.nextElement();
            final Manifest manifest = new Manifest(resource.openStream());
            if ("java-webauthn-server".equals(manifest.getMainAttributes().getValue("Implementation-Id"))) {
                return Optional.ofNullable(manifest.getMainAttributes().getValue("Implementation-Version"));
            }
        }

        return Optional.empty();
    }

}
