package com.yubico.u2f;

import com.google.common.net.InetAddresses;
import com.yubico.u2f.exceptions.U2fBadConfigurationException;

import java.net.URI;
import java.net.URISyntaxException;

public class AppId {

    public static final String DISABLE_INSTRUCTIONS = "To disable this check, create your U2F object using U2F.withoutAppIdValidation()";

    /**
     * Throws {@link U2fBadConfigurationException} if the given App ID is found to be incompatible with the U2F specification or any major
     * U2F Client implementation.
     *
     * @param appId the App ID to be validated
     */
    public static void checkIsValid(String appId) {
        if(!appId.contains(":")) {
            throw new U2fBadConfigurationException("App ID does not look like a valid facet or URL. Web facets must start with 'https://'. " + DISABLE_INSTRUCTIONS);
        }
        if(appId.startsWith("http:")) {
            throw new U2fBadConfigurationException("HTTP is not supported for App IDs (by Chrome). Use HTTPS instead. " + DISABLE_INSTRUCTIONS);
        }
        if(appId.startsWith("https://")) {
            URI url = null;
            try {
                url = new URI(appId);
            } catch (URISyntaxException e) {
                throw new U2fBadConfigurationException("App ID looks like a HTTPS URL, but has syntax errors.", e);
            }
            if (InetAddresses.isInetAddress(url.getAuthority()) || (url.getHost() != null && InetAddresses.isInetAddress(url.getHost()))) {
                throw new U2fBadConfigurationException("App ID must not be an IP-address, since it is not supported (by Chrome). Use a host name instead. " + DISABLE_INSTRUCTIONS);
            }
        }
    }
}
