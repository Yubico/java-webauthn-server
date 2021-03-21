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
      String origin, Set<String> allowedOrigins, boolean allowPort, boolean allowSubdomain) {
    log.trace("isAllowed({}, {}, {}, {})", origin, allowedOrigins, allowPort, allowSubdomain);

    URL tmpOriginUrl;
    try {
      tmpOriginUrl = new URL(origin);
    } catch (MalformedURLException e) {
      log.debug("Origin in client data is not a valid URL; will only match exactly: {}", origin);
      tmpOriginUrl = null;
    }
    final URL originUrl = tmpOriginUrl;

    return allowedOrigins.stream()
        .anyMatch(
            allowedOriginString -> {
              if (allowedOriginString.equals(origin)) {
                log.debug("Exact match: {} == {}", origin, allowedOriginString);
                return true;
              } else if (originUrl != null && (allowPort || allowSubdomain)) {
                final URL allowedOrigin;
                try {
                  allowedOrigin = new URL(allowedOriginString);
                } catch (MalformedURLException e) {
                  log.error(
                      "Allowed origin is not a valid URL; skipping port/subdomain matching: {}",
                      allowedOriginString);
                  return false;
                }

                final boolean portAccepted = isPortAccepted(allowPort, allowedOrigin, originUrl);
                final boolean domainAccepted =
                    isDomainAccepted(allowSubdomain, allowedOrigin, originUrl);

                log.debug("portAccepted: {}, domainAccepted: {}", portAccepted, domainAccepted);
                return portAccepted && domainAccepted;
              } else {
                log.debug("No match: {} != {}", origin, allowedOriginString);
                return false;
              }
            });
  }

  private static boolean isPortAccepted(boolean allowAnyPort, URL allowedOrigin, URL origin) {
    if (allowAnyPort) {
      return true;
    } else {
      return origin.getPort() == allowedOrigin.getPort();
    }
  }

  private static boolean isDomainAccepted(boolean allowSubdomain, URL allowedOrigin, URL origin) {
    final String allowedDomain = allowedOrigin.getHost();
    final String originDomain = origin.getHost();

    if (allowSubdomain) {
      return originDomain.equals(allowedDomain) || originDomain.endsWith("." + allowedDomain);
    } else {
      return originDomain.equals(allowedDomain);
    }
  }
}
