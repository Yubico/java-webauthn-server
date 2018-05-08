/*
 * Copyright 2014 Yubico.
 * Copyright 2014 Google Inc. All rights reserved.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://developers.google.com/open-source/licenses/bsd
 */

package com.yubico.u2f.testdata;

import com.google.common.collect.ImmutableSet;
import com.yubico.u2f.TestUtils;
import com.yubico.u2f.crypto.BouncyCastleCrypto;
import com.yubico.u2f.crypto.Crypto;
import com.yubico.u2f.data.messages.key.util.U2fB64Encoding;
import java.util.Set;

final public class TestVectors {
    private final static Crypto crypto = new BouncyCastleCrypto();

    //Test vectors from FIDO U2F: Raw Message Formats - Draft 4
    public static final int COUNTER_VALUE = 1;
    public static final Set<String> TRUSTED_DOMAINS = ImmutableSet.of("http://example.com");
    public static final String APP_ID_ENROLL = "http://example.com";
    public static final byte[] APP_ID_ENROLL_SHA256 = crypto.hash(APP_ID_ENROLL);
    public static final String APP_ID_SIGN = "https://gstatic.com/securitykey/a/example.com";
    public static final byte[] APP_ID_SIGN_SHA256 = crypto.hash(APP_ID_SIGN);
    public static final String ORIGIN = "http://example.com";
    public static final String SERVER_CHALLENGE_REGISTER_BASE64 =
            "vqrS6WXDe1JUs5_c3i4-LkKIHRr-3XVb3azuA5TifHo";
    public static final String SERVER_CHALLENGE_SIGN_BASE64 = "opsXqUifDriAAmWclinfbS0e-USY0CgyJHe_Otd7z8o";

    public static final String CHANNEL_ID_STRING =
            "{"
                    + "\"kty\":\"EC\","
                    + "\"crv\":\"P-256\","
                    + "\"x\":\"HzQwlfXX7Q4S5MtCCnZUNBw3RMzPO9tOyWjBqRl4tJ8\","
                    + "\"y\":\"XVguGFLIZx1fXg3wNqfdbn75hi4-_7-BxhMljw42Ht4\""
                    + "}";
    public static final String CLIENT_DATA_REGISTER = String.format(
            "{"
                    + "\"typ\":\"navigator.id.finishEnrollment\","
                    + "\"challenge\":\"%s\","
                    + "\"cid_pubkey\":%s,"
                    + "\"origin\":\"%s\"}",
            SERVER_CHALLENGE_REGISTER_BASE64,
            CHANNEL_ID_STRING,
            ORIGIN);
    public static final String CLIENT_DATA_REGISTRATION_BASE64 = TestUtils.BASE64.encode(CLIENT_DATA_REGISTER.getBytes());
    public static final byte[] CLIENT_DATA_ENROLL_SHA256 = crypto.hash(CLIENT_DATA_REGISTER
            .getBytes());
    public static final String CLIENT_DATA_SIGN = String.format(
            "{"
                    + "\"typ\":\"navigator.id.getAssertion\","
                    + "\"challenge\":\"%s\","
                    + "\"cid_pubkey\":%s,"
                    + "\"origin\":\"%s\"}",
            SERVER_CHALLENGE_SIGN_BASE64,
            CHANNEL_ID_STRING,
            ORIGIN);
    public static final String CLIENT_DATA_SIGN_BASE64 = U2fB64Encoding.encode(CLIENT_DATA_SIGN.getBytes());
    public static final byte[] CLIENT_DATA_SIGN_SHA256 = TestUtils.HEX.decode(
            "ccd6ee2e47baef244d49a222db496bad0ef5b6f93aa7cc4d30c4821b3b9dbc57");
    public static final byte[] REGISTRATION_REQUEST_DATA = TestUtils.HEX.decode(
            "4142d21c00d94ffb9d504ada8f99b721f4b191ae4e37ca0140f696b6983cfacb"
                    + "f0e6a6a97042a4f1f1c87f5f7d44315b2d852c2df5c7991cc66241bf7072d1c4");
    public static final byte[] REGISTRATION_RESPONSE_DATA = TestUtils.HEX.decode(
            "0504b174bc49c7ca254b70d2e5c207cee9cf174820ebd77ea3c65508c26da51b"
                    + "657c1cc6b952f8621697936482da0a6d3d3826a59095daf6cd7c03e2e60385d2"
                    + "f6d9402a552dfdb7477ed65fd84133f86196010b2215b57da75d315b7b9e8fe2"
                    + "e3925a6019551bab61d16591659cbaf00b4950f7abfe6660e2e006f76868b772"
                    + "d70c253082013c3081e4a003020102020a47901280001155957352300a06082a"
                    + "8648ce3d0403023017311530130603550403130c476e756262792050696c6f74"
                    + "301e170d3132303831343138323933325a170d3133303831343138323933325a"
                    + "3031312f302d0603550403132650696c6f74476e756262792d302e342e312d34"
                    + "373930313238303030313135353935373335323059301306072a8648ce3d0201"
                    + "06082a8648ce3d030107034200048d617e65c9508e64bcc5673ac82a6799da3c"
                    + "1446682c258c463fffdf58dfd2fa3e6c378b53d795c4a4dffb4199edd7862f23"
                    + "abaf0203b4b8911ba0569994e101300a06082a8648ce3d040302034700304402"
                    + "2060cdb6061e9c22262d1aac1d96d8c70829b2366531dda268832cb836bcd30d"
                    + "fa0220631b1459f09e6330055722c8d89b7f48883b9089b88d60d1d9795902b3"
                    + "0410df304502201471899bcc3987e62e8202c9b39c33c19033f7340352dba80f"
                    + "cab017db9230e402210082677d673d891933ade6f617e5dbde2e247e70423fd5"
                    + "ad7804a6d3d3961ef871");

    public static final String REGISTRATION_DATA_BASE64 = U2fB64Encoding.encode(REGISTRATION_RESPONSE_DATA);

    public static final byte[] REGISTRATION_RESPONSE_DATA_WITH_DIFFERENT_APP_ID = TestUtils.HEX.decode(
                "0504b174bc49c7ca254b70d2e5c207cee9cf174820ebd77ea3c65508c26da51b"
                    + "657c1cc6b952f8621697936482da0a6d3d3826a59095daf6cd7c03e2e60385d2"
                    + "f6d9402a552dfdb7477ed65fd84133f86196010b2215b57da75d315b7b9e8fe2"
                    + "e3925a6019551bab61d16591659cbaf00b4950f7abfe6660e2e006f76868b772"
                    + "d70c253082013c3081e4a003020102020a47901280001155957352300a06082a"
                    + "8648ce3d0403023017311530130603550403130c476e756262792050696c6f74"
                    + "301e170d3132303831343138323933325a170d3133303831343138323933325a"
                    + "3031312f302d0603550403132650696c6f74476e756262792d302e342e312d34"
                    + "373930313238303030313135353935373335323059301306072a8648ce3d0201"
                    + "06082a8648ce3d030107034200048d617e65c9508e64bcc5673ac82a6799da3c"
                    + "1446682c258c463fffdf58dfd2fa3e6c378b53d795c4a4dffb4199edd7862f23"
                    + "abaf0203b4b8911ba0569994e101300a06082a8648ce3d040302034700304402"
                    + "2060cdb6061e9c22262d1aac1d96d8c70829b2366531dda268832cb836bcd30d"
                    + "fa0220631b1459f09e6330055722c8d89b7f48883b9089b88d60d1d9795902b3"
                    + "0410df3046022100d2b4702fea46b322c5addd921b3f4f0fb15c69737fe7441e"
                    + "b764c03dc8f49d09022100eef7dcdf6070d8e5a45ed6be18dfc036ebf8b4faaa"
                    + "ce7287b56e7fac1d2cb552");
    public static final String REGISTRATION_DATA_WITH_DIFFERENT_APP_ID_BASE64 = U2fB64Encoding.encode(REGISTRATION_RESPONSE_DATA_WITH_DIFFERENT_APP_ID);

    public static final byte[] REGISTRATION_RESPONSE_DATA_WITH_DIFFERENT_CLIENT_DATA_TYPE = TestUtils.HEX.decode(
        "0504b174bc49c7ca254b70d2e5c207cee9cf174820ebd77ea3c65508c26da51b"
            + "657c1cc6b952f8621697936482da0a6d3d3826a59095daf6cd7c03e2e60385d2"
            + "f6d9402a552dfdb7477ed65fd84133f86196010b2215b57da75d315b7b9e8fe2"
            + "e3925a6019551bab61d16591659cbaf00b4950f7abfe6660e2e006f76868b772"
            + "d70c253082013c3081e4a003020102020a47901280001155957352300a06082a"
            + "8648ce3d0403023017311530130603550403130c476e756262792050696c6f74"
            + "301e170d3132303831343138323933325a170d3133303831343138323933325a"
            + "3031312f302d0603550403132650696c6f74476e756262792d302e342e312d34"
            + "373930313238303030313135353935373335323059301306072a8648ce3d0201"
            + "06082a8648ce3d030107034200048d617e65c9508e64bcc5673ac82a6799da3c"
            + "1446682c258c463fffdf58dfd2fa3e6c378b53d795c4a4dffb4199edd7862f23"
            + "abaf0203b4b8911ba0569994e101300a06082a8648ce3d040302034700304402"
            + "2060cdb6061e9c22262d1aac1d96d8c70829b2366531dda268832cb836bcd30d"
            + "fa0220631b1459f09e6330055722c8d89b7f48883b9089b88d60d1d9795902b3"
            + "0410df30450220176386c89021f4335d953c56a0c831f98380dc198c95794a85"
            + "b08f0c4ba849ff022100a10114749d0c28e13a9ffe6dde6e622c33163b249ac1"
            + "ffb1c8e25b3cc4907e3c");
    public static final String REGISTRATION_DATA_WITH_DIFFERENT_CLIENT_DATA_TYPE_BASE64 = U2fB64Encoding.encode(REGISTRATION_RESPONSE_DATA_WITH_DIFFERENT_CLIENT_DATA_TYPE);

    public static final byte[] KEY_HANDLE = TestUtils.HEX.decode(
            "2a552dfdb7477ed65fd84133f86196010b2215b57da75d315b7b9e8fe2e3925a"
                    + "6019551bab61d16591659cbaf00b4950f7abfe6660e2e006f76868b772d70c25");
    public static final String KEY_HANDLE_BASE64 = U2fB64Encoding.encode(KEY_HANDLE);
    public static final byte[] USER_PUBLIC_KEY_REGISTER_HEX = TestUtils.HEX.decode(
            "04b174bc49c7ca254b70d2e5c207cee9cf174820ebd77ea3c65508c26da51b65"
                    + "7c1cc6b952f8621697936482da0a6d3d3826a59095daf6cd7c03e2e60385d2f6"
                    + "d9");
    public static final String USER_PUBLIC_KEY_SIGN_HEX = "BNNo8bZlut48M6IPHkKcd1DVAzZgwBkRnSmqS6erwEqnyApGu-EcqMtWdNdPMfipA_a60QX7ardK7-9NuLACXh0";
    public static final byte[] SIGN_RESPONSE_DATA = TestUtils.HEX.decode(
            "0100000001304402204b5f0cd17534cedd8c34ee09570ef542a353df4436030c"
                    + "e43d406de870b847780220267bb998fac9b7266eb60e7cb0b5eabdfd5ba9614f"
                    + "53c7b22272ec10047a923f");
    public static final String SIGN_RESPONSE_DATA_BASE64 = U2fB64Encoding.encode(SIGN_RESPONSE_DATA);
    public static final byte[] EXPECTED_REGISTER_SIGNED_BYTES = TestUtils.HEX.decode(
            "00f0e6a6a97042a4f1f1c87f5f7d44315b2d852c2df5c7991cc66241bf7072d1"
                    + "c44142d21c00d94ffb9d504ada8f99b721f4b191ae4e37ca0140f696b6983cfa"
                    + "cb2a552dfdb7477ed65fd84133f86196010b2215b57da75d315b7b9e8fe2e392"
                    + "5a6019551bab61d16591659cbaf00b4950f7abfe6660e2e006f76868b772d70c"
                    + "2504b174bc49c7ca254b70d2e5c207cee9cf174820ebd77ea3c65508c26da51b"
                    + "657c1cc6b952f8621697936482da0a6d3d3826a59095daf6cd7c03e2e60385d2"
                    + "f6d9");
    public static final byte[] EXPECTED_SIGN_SIGNED_BYTES = TestUtils.HEX.decode(
            "4b0be934baebb5d12d26011b69227fa5e86df94e7d94aa2949a89f2d493992ca"
                    + "0100000001ccd6ee2e47baef244d49a222db496bad0ef5b6f93aa7cc4d30c482"
                    + "1b3b9dbc57");
    public static final byte[] SIGNATURE_REGISTER = TestUtils.HEX.decode(
            "304502201471899bcc3987e62e8202c9b39c33c19033f7340352dba80fcab017"
                    + "db9230e402210082677d673d891933ade6f617e5dbde2e247e70423fd5ad7804"
                    + "a6d3d3961ef871");
    public static final byte[] SIGNATURE_SIGN = TestUtils.HEX.decode(
            "304402204b5f0cd17534cedd8c34ee09570ef542a353df4436030ce43d406de8"
                    + "70b847780220267bb998fac9b7266eb60e7cb0b5eabdfd5ba9614f53c7b22272"
                    + "ec10047a923f");

    public static final byte[] SIGN_RESPONSE_INVALID_USER_PRESENCE = TestUtils.HEX.decode(
            "00000000013045022100adf3521ceb4e143fb3966d3017510bfbc9085a44ff13c6945aadd8"
                    + "e26ec5cc00022004916d120830f2ee44ab3c6c58c80a3dd6f5a09b01599e686d"
                    + "ea2e7288903cae");
    public static final String SIGN_RESPONSE_INVALID_USER_PRESENCE_BASE64 = U2fB64Encoding.encode(SIGN_RESPONSE_INVALID_USER_PRESENCE);
}
