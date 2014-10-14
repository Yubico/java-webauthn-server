/*
 * Snippet from:
 *
 * http://cipherious.wordpress.com/2013/05/20/constructing-an-x-509-certificate-using-bouncy-castle/
 */

package com.yubico.u2f.server.impl;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509ExtensionUtils;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Date;

public class DummyCertificateGenerator {
  public static X509Certificate generate() throws Exception {
    Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

    //Generate Keypair
    SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
    KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA");
    kpGen.initialize(512, random);
    KeyPair keyPair = kpGen.generateKeyPair();
    PublicKey RSAPubKey = keyPair.getPublic();
    PrivateKey RSAPrivateKey = keyPair.getPrivate();

    //Subject and Issuer DN
    X500Name subjectDN = new X500Name("C=US,O=Cyberdyne,OU=PKI,CN=SecureCA");
    X500Name issuerDN = new X500Name("C=US,O=Cyberdyne,OU=PKI,CN=SecureCA");

    //SubjectPublicKeyInfo
    SubjectPublicKeyInfo subjPubKeyInfo = new SubjectPublicKeyInfo(ASN1Sequence.getInstance(RSAPubKey.getEncoded()));

    X509v3CertificateBuilder certGen = new X509v3CertificateBuilder(issuerDN, BigInteger.ONE,
            new Date(), new Date(), subjectDN, subjPubKeyInfo);

    DigestCalculator digCalc = new BcDigestCalculatorProvider().get(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1));
    X509ExtensionUtils x509ExtensionUtils = new X509ExtensionUtils(digCalc);

    //Subject Key Identifier
    certGen.addExtension(Extension.subjectKeyIdentifier, false, x509ExtensionUtils.createSubjectKeyIdentifier(subjPubKeyInfo));

    //Authority Key Identifier
    certGen.addExtension(Extension.authorityKeyIdentifier, false, x509ExtensionUtils.createAuthorityKeyIdentifier(subjPubKeyInfo));

    //Key Usage
    certGen.addExtension(Extension.keyUsage, false, new KeyUsage(KeyUsage.keyCertSign));

    //Extended Key Usage
    KeyPurposeId[] EKU = new KeyPurposeId[2];
    EKU[0] = KeyPurposeId.id_kp_emailProtection;
    EKU[1] = KeyPurposeId.id_kp_serverAuth;

    certGen.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(EKU));

    //Content Signer
    ContentSigner sigGen = new JcaContentSignerBuilder("SHA1WithRSAEncryption").setProvider("BC").build(RSAPrivateKey);

    //Certificate
    return new JcaX509CertificateConverter().setProvider("BC").getCertificate(certGen.build(sigGen));
  }
}
