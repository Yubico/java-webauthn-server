package com.yubico.gradle.plugins.signing.signatory.gpg;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.apache.commons.io.IOUtils;
import org.gradle.plugins.signing.signatory.SignatorySupport;

class GpgSignatory extends SignatorySupport {

    private final String keyId;

    public GpgSignatory(String keyId) {
        if (keyId == null) {
            throw new IllegalArgumentException("keyId must not be null.");
        }
        this.keyId = keyId;
    }

    @Override
    public String getName() {
        return keyId;
    }

    @Override
    public void sign(InputStream toSign, OutputStream destination) {
        try {
            Process gpgProcess = new ProcessBuilder("gpg", "--local-user", keyId, "--detach-sign", "--use-agent").start();

            IOUtils.copy(toSign, gpgProcess.getOutputStream());
            gpgProcess.getOutputStream().close();

            gpgProcess.waitFor();

            IOUtils.copy(gpgProcess.getInputStream(), destination);
        } catch (IOException|InterruptedException e) {
            throw new RuntimeException(e);
        }
    }

}
