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
        return allowedOrigins.stream().anyMatch(allowedOriginString -> {
            if (allowedOriginString.equals(origin)) {
                return true;
            } else {
                final URL allowedOrigin;
                try {
                    allowedOrigin = new URL(allowedOriginString);
                } catch (MalformedURLException e) {
                    return false;
                }

                final URL originUrl;
                try {
                    originUrl = new URL(origin);
                } catch (MalformedURLException e) {
                    log.debug("Invalid origin in client data: {}", origin);
                    return false;
                }

                if (!allowPort && originUrl.getPort() != allowedOrigin.getPort()) {
                    return false;
                }

                final String allowedDomain = allowedOrigin.getHost();
                final String originDomain = originUrl.getHost();

                if (allowSubdomain) {
                    return originDomain.endsWith("." + allowedDomain);
                } else {
                    return originDomain.equals(allowedDomain);
                }
            }
        });
    }

}
