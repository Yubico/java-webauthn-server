package com.yubico.u2f;

import com.google.common.net.InetAddresses;
import com.yubico.u2f.exceptions.U2fBadConfigurationException;
import java.net.URI;
import java.net.URISyntaxException;

public class AppId {

    public final String value;

    public AppId(String appId) throws U2fBadConfigurationException {
        checkIsValid(appId);
        this.value = appId;
    }

    /**
     * Throws {@link U2fBadConfigurationException} if the given App ID is found to be incompatible with the U2F specification or any major
     * U2F Client implementation.
     *
     * @param appId the App ID to be validated
     */
    private static void checkIsValid(String appId) throws U2fBadConfigurationException {
        if(!appId.contains(":")) {
            throw new U2fBadConfigurationException("App ID does not look like a valid facet or URL. Web facets must start with 'https://'.");
        }
        if(appId.startsWith("http:")) {
            throw new U2fBadConfigurationException("HTTP is not supported for App IDs (by Chrome). Use HTTPS instead.");
        }
        if(appId.startsWith("https://")) {
            URI url = checkValidUrl(appId);
            checkPathIsNotSlash(url);
            checkNotIpAddress(url);
        }
    }

    private static void checkPathIsNotSlash(URI url) throws U2fBadConfigurationException {
        if("/".equals(url.getPath())) {
            throw new U2fBadConfigurationException("The path of the URL set as App ID is '/'. This is probably not what you want -- remove the trailing slash of the App ID URL.");
        }
    }

    private static URI checkValidUrl(String appId) throws U2fBadConfigurationException {
        try {
            return new URI(appId);
        } catch (URISyntaxException e) {
            throw new U2fBadConfigurationException("App ID looks like a HTTPS URL, but has syntax errors.", e);
        }
    }

    private static void checkNotIpAddress(URI url) throws U2fBadConfigurationException {
        if (InetAddresses.isInetAddress(url.getAuthority()) || (url.getHost() != null && InetAddresses.isInetAddress(url.getHost()))) {
            throw new U2fBadConfigurationException("App ID must not be an IP-address, since it is not supported (by Chrome). Use a host name instead.");
        }
    }
}
