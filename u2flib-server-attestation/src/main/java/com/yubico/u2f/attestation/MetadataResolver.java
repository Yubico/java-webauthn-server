package com.yubico.u2f.attestation;

import java.security.cert.X509Certificate;

/**
 * Created by dain on 12/5/14.
 */
public interface MetadataResolver {
    void importMetadata(MetadataObject metadata) throws InvalidMetadataException;

    MetadataObject resolve(X509Certificate attestationCertificate);

    class InvalidMetadataException extends Exception {
        public InvalidMetadataException(String message, Throwable cause) {
            super(message, cause);
        }

        public InvalidMetadataException(String message) {
            super(message);
        }

        public InvalidMetadataException(Throwable cause) {
            super(cause);
        }

        public InvalidMetadataException() {
            super();
        }
    }
}
