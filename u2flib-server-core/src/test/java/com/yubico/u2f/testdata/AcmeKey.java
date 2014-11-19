package com.yubico.u2f.testdata;

import com.yubico.u2f.TestUtils;
import com.yubico.u2f.data.messages.key.util.U2fB64Encoding;

import java.security.cert.X509Certificate;

import static com.yubico.u2f.TestUtils.fetchCertificate;

public class AcmeKey {

    public static final X509Certificate ATTESTATION_CERTIFICATE =
            fetchCertificate(GnubbyKey.class.getResourceAsStream("acme/attestation-certificate.der"));

    public static final String CLIENT_DATA_BASE64 = TestVectors.CLIENT_DATA_REGISTRATION_BASE64;
    public static final byte[] REGISTRATION_DATA = TestUtils.HEX.decode(
            "0504478e16bbdbbb741a660a000314a8b6bd63095196ed704c52eebc0fa02a61"
                    + "8f19ff59df18451a11cee43defd9a29b5710f63dfc671f752b1b0c6ca76c8427"
                    + "af2d403c2415e1760d1108105720c6069a9039c99d09f76909c36d9efc350937"
                    + "31f85f55ac6d73ea69de7d9005ae9507b95e149e19676272fc202d949a3ab151"
                    + "b96870308201443081eaa0030201020209019189ffffffff5183300a06082a86"
                    + "48ce3d040302301b3119301706035504031310476e756262792048534d204341"
                    + "2030303022180f32303132303630313030303030305a180f3230363230353331"
                    + "3233353935395a30303119301706035504031310476f6f676c6520476e756262"
                    + "7920763031133011060355042d030a00019189ffffffff51833059301306072a"
                    + "8648ce3d020106082a8648ce3d030107034200041f1302f12173a9cbea83d06d"
                    + "755411e582a87fbb5850eddcf3607ec759a4a12c3cb392235e8d5b17caee1b34"
                    + "e5b5eb548649696257f0ea8efb90846f88ad5f72300a06082a8648ce3d040302"
                    + "0349003046022100b4caea5dc60fbf9f004ed84fc4f18522981c1c303155c082"
                    + "74e889f3f10c5b23022100faafb4f10b92f4754e3b08b5af353f78485bc903ec"
                    + "e7ea911264fc1673b6598f3046022100f3be1bf12cbf0be7eab5ea32f3664edb"
                    + "18a24d4999aac5aa40ff39cf6f34c9ed022100ce72631767367467dfe2aecf6a"
                    + "5a4eba9779fac65f5ca8a2c325b174ee4769ac");
    public static final String REGISTRATION_DATA_BASE64 = U2fB64Encoding
            .encode(REGISTRATION_DATA);
    public static final String KEY_HANDLE = "PCQV4XYNEQgQVyDGBpqQOcmdCfdpCcNtnvw1CTcx-F9VrG1z6mnefZAFrpUHuV4UnhlnYnL8IC2UmjqxUblocA";
    public static final String USER_PUBLIC_KEY_B64 = "BEeOFrvbu3QaZgoAAxSotr1jCVGW7XBMUu68D6AqYY8Z_1nfGEUaEc7kPe_ZoptXEPY9_GcfdSsbDGynbIQnry0";
}
