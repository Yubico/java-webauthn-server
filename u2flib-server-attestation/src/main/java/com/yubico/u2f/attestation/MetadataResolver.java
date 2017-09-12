/* Copyright 2015 Yubico */

package com.yubico.u2f.attestation;

import java.security.cert.X509Certificate;
import java.util.List;

public interface MetadataResolver {
    MetadataObject resolve(X509Certificate attestationCertificate);

    /**
     * Attempt to resolve a chain of certificates
     *
     * <p>
     * This method will return the first non-null result, if any, of calling
     * {@link #resolve(X509Certificate)} with each of the certificates in
     * <code>certificateChain</code> in order, while also verifying that the
     * next attempted certificate has signed the previous certificate.
     * </p>
     *
     * @param certificateChain a certificate chain, where each certificate in
     *          the list should be signed by the following certificate.
     * @return The first non-null result, if any, of calling {@link
     *           #resolve(X509Certificate)} for each of the certificates in the
     *           <code>certificateChain</code>. If the chain of signatures is
     *           broken before finding such a result, <code>null</code> is
     *           returned.
     */
    MetadataObject resolve(List<X509Certificate> certificateChain);
}
