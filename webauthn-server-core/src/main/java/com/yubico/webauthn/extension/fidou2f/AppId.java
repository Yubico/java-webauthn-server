package com.yubico.webauthn.extension.fidou2f;

import com.google.common.net.InetAddresses;
import com.yubico.webauthn.exception.BadConfigurationException;
import java.net.URI;
import java.net.URISyntaxException;

public class AppId {

    public final String id;

    public AppId(String appId) throws BadConfigurationException {
        checkIsValid(appId);
        this.id = appId;
    }

    /**
     * Throws {@link BadConfigurationException} if the given App ID is found to be incompatible with the U2F specification or any major
     * U2F Client implementation.
     *
     * @param appId the App ID to be validated
     */
    private static void checkIsValid(String appId) throws BadConfigurationException {
        if(!appId.contains(":")) {
            throw new BadConfigurationException("App ID does not look like a valid facet or URL. Web facets must start with 'https://'.");
        }
        if(appId.startsWith("http:")) {
            throw new BadConfigurationException("HTTP is not supported for App IDs (by Chrome). Use HTTPS instead.");
        }
        if(appId.startsWith("https://")) {
            URI url = checkValidUrl(appId);
            checkPathIsNotSlash(url);
            checkNotIpAddress(url);
        }
    }

    private static void checkPathIsNotSlash(URI url) throws BadConfigurationException {
        if("/".equals(url.getPath())) {
            throw new BadConfigurationException("The path of the URL set as App ID is '/'. This is probably not what you want -- remove the trailing slash of the App ID URL.");
        }
    }

    private static URI checkValidUrl(String appId) throws BadConfigurationException {
        try {
            return new URI(appId);
        } catch (URISyntaxException e) {
            throw new BadConfigurationException("App ID looks like a HTTPS URL, but has syntax errors.", e);
        }
    }

    private static void checkNotIpAddress(URI url) throws BadConfigurationException {
        if (InetAddresses.isInetAddress(url.getAuthority()) || (url.getHost() != null && InetAddresses.isInetAddress(url.getHost()))) {
            throw new BadConfigurationException("App ID must not be an IP-address, since it is not supported (by Chrome). Use a host name instead.");
        }
    }
}
