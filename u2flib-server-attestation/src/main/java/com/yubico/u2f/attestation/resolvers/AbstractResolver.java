package com.yubico.u2f.attestation.resolvers;

import com.yubico.u2f.attestation.MetadataObject;
import com.yubico.u2f.attestation.MetadataResolver;
import java.security.cert.X509Certificate;
import java.util.Iterator;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public abstract class AbstractResolver implements MetadataResolver {

    private static final Logger logger = LoggerFactory.getLogger(AbstractResolver.class);

    @Override
    public MetadataObject resolve(List<X509Certificate> certificateChain) {

        Iterator<X509Certificate> it = certificateChain.iterator();
        if (it.hasNext() == false) {
            return null;
        }

        X509Certificate cert = it.next();

        while (it.hasNext()) {
            MetadataObject resolved = resolve(cert);

            if (resolved != null) {
                return resolved;
            } else {
                logger.trace("Could not resolve certificate [{}] - trying next element in certificate chain.", cert);

                X509Certificate signingCert = it.next();

                try {
                    cert.verify(signingCert.getPublicKey());
                } catch (Exception e) {
                    logger.debug("Failed to verify that certificate [{}] was signed by certificate [{}].", cert, signingCert, e);
                    return null;
                }
            }

        }

        return null;
    }

}
