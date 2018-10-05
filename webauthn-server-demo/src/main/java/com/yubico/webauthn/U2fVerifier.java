package com.yubico.webauthn;

import com.fasterxml.jackson.databind.JsonNode;
import com.yubico.internal.util.CertificateParser;
import com.yubico.internal.util.ExceptionUtil;
import com.yubico.internal.util.WebAuthnCodecs;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.exception.Base64UrlException;
import com.yubico.webauthn.extension.appid.AppId;
import demo.webauthn.data.RegistrationRequest;
import demo.webauthn.data.U2fRegistrationResponse;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class U2fVerifier {

    private static final Crypto crypto = new BouncyCastleCrypto();

    public static boolean verify(AppId appId,  RegistrationRequest request, U2fRegistrationResponse response) throws CertificateException, IOException, Base64UrlException {
        final ByteArray appIdHash = crypto.hash(appId.getId());
        final ByteArray clientDataHash = crypto.hash(response.getCredential().getU2fResponse().getClientDataJSON());

        final JsonNode clientData = WebAuthnCodecs.json().readTree(response.getCredential().getU2fResponse().getClientDataJSON().getBytes());
        final String challengeBase64 = clientData.get("challenge").textValue();

        ExceptionUtil.assure(
            request.getPublicKeyCredentialCreationOptions().getChallenge().equals(ByteArray.fromBase64Url(challengeBase64)),
            "Wrong challenge."
        );

        InputStream attestationCertAndSignatureStream = new ByteArrayInputStream(response.getCredential().getU2fResponse().getAttestationCertAndSignature().getBytes());

        final X509Certificate attestationCert = CertificateParser.parseDer(attestationCertAndSignatureStream);

        byte[] signatureBytes = new byte[attestationCertAndSignatureStream.available()];
        attestationCertAndSignatureStream.read(signatureBytes);
        final ByteArray signature = new ByteArray(signatureBytes);

        return new U2fRawRegisterResponse(
            response.getCredential().getU2fResponse().getPublicKey(),
            response.getCredential().getU2fResponse().getKeyHandle(),
            attestationCert,
            signature
        ).verifySignature(
            appIdHash,
            clientDataHash
        );
    }

}
