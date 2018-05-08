package com.yubico.u2f;

import com.yubico.u2f.exceptions.U2fBadConfigurationException;
import org.junit.Test;

import static junit.framework.TestCase.assertFalse;
import static junit.framework.TestCase.assertTrue;

public class AppIdTest {

    @Test
    public void validUrls() {
        assertTrue(isValid("https://www.example.com"));
        assertTrue(isValid("https://internal-server"));
        assertTrue(isValid("https://åäö.se:8443"));
        assertTrue(isValid("https://localhost:8443/myAppId.json"));
    }

    @Test
    public void validUris() {
        assertTrue(isValid("android:apk-key-hash:585215fd5153209a7e246f53286035838a0be227"));
        assertTrue(isValid("ios:bundle-id:com.example.Example"));
    }

    @Test
    public void disallowHttp() {
        assertFalse(isValid("http://www.example.com"));
    }

    @Test
    public void disallowSlashAsPath() {
        assertFalse(isValid("https://www.example.com/"));
    }

    @Test
    public void disallowIP() {
        assertFalse(isValid("https://127.0.0.1:8443"));
        assertFalse(isValid("https://127.0.0.1"));
        assertFalse(isValid("https://127.0.0.1/foo"));
        assertFalse(isValid("https://2001:0db8:0000:0000:0000:ff00:0042:8329"));
        assertFalse(isValid("https://2001:0db8:0000:0000:0000:ff00:0042:8329/åäö"));
    }

    @Test
    public void badSyntax() {
        assertFalse(isValid("https://bad[syntax]"));
    }

    private static boolean isValid(String appId) {
        try {
            new AppId(appId);
            return true;
        } catch (U2fBadConfigurationException e) {
            return false;
        }

    }
}
