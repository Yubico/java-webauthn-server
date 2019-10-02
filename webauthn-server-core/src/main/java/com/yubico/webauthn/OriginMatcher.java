package com.yubico.webauthn;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Set;
import lombok.experimental.UtilityClass;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@UtilityClass
class OriginMatcher {

    static boolean isAllowed(
        String origin,
        Set<String> allowedOrigins,
        boolean allowPort,
        boolean allowSubdomain
    ) {
        log.trace("isAllowed({}, {}, {}, {})", origin, allowedOrigins, allowPort, allowSubdomain);

        final URL originUrl;
        {
            URL tmpOriginUrl;
            try {
                tmpOriginUrl = new URL(origin);
            } catch (MalformedURLException e) {
                log.debug("Origin in client data is an invalid URL; will only match exactly: {}", origin);
                tmpOriginUrl = null;
            }
            originUrl = tmpOriginUrl;
        }

        return allowedOrigins.stream().anyMatch(allowedOriginString -> {
            if (allowedOriginString.equals(origin)) {
                log.debug("Exact match: {} == {}", origin, allowedOriginString);
                return true;
            } else if (originUrl != null && (allowPort || allowSubdomain)) {
                final URL allowedOrigin;
                try {
                    allowedOrigin = new URL(allowedOriginString);
                } catch (MalformedURLException e) {
                    log.error("Allowed origin is an invalid URL; skipped for port/subdomain matching: {}", allowedOriginString);
                    return false;
                }

                final boolean portAccepted;
                final boolean domainAccepted;

                if (allowPort) {
                    portAccepted = true;
                } else {
                    portAccepted = originUrl.getPort() == allowedOrigin.getPort();
                }

                final String allowedDomain = allowedOrigin.getHost();
                final String originDomain = originUrl.getHost();

                if (allowSubdomain) {
                    domainAccepted = originDomain.equals(allowedDomain) || originDomain.endsWith("." + allowedDomain);
                } else {
                    domainAccepted = originDomain.equals(allowedDomain);
                }

                log.debug("portAccepted: {}, domainAccepted: {}", portAccepted, domainAccepted);
                return portAccepted && domainAccepted;
            } else {
                log.debug("No match: {} != {}", origin, allowedOriginString);
                return false;
            }
        });
    }

}
