package com.yubico.webauthn;

import java.util.Set;
import lombok.experimental.UtilityClass;

@UtilityClass
class OriginMatcher {

    static boolean isAllowed(
        String origin,
        Set<String> allowedOrigins,
        boolean allowPort,
        boolean allowSubdomain
    ) {
        return allowedOrigins.stream().anyMatch(allowedOriginString ->
            allowedOriginString.equals(origin)
        );
    }

}
