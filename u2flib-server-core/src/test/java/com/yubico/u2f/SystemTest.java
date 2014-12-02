package com.yubico.u2f;

import com.google.common.collect.ImmutableSet;
import com.yubico.u2f.data.DeviceRegistration;
import com.yubico.u2f.data.messages.AuthenticateRequest;
import com.yubico.u2f.data.messages.AuthenticateResponse;
import com.yubico.u2f.data.messages.RegisterRequest;
import com.yubico.u2f.data.messages.RegisterResponse;
import org.junit.Ignore;

import java.util.Scanner;

@Ignore("Includes manual steps")
public class SystemTest {

    public static final ImmutableSet<String> TRUSTED_DOMAINS = ImmutableSet.of("http://example.com");
    public static final String APP_ID = "my-app";
    private static Scanner scan = new Scanner(System.in);
    private static final U2fPrimitives u2f = new U2fPrimitives();

    /*
      For manual testing with physical keys. Can e.g. be combined with these libu2f-host commands:

        u2f-host -aregister -o http://example.com
        u2f-host -aauthenticate -o http://example.com
     */
    public static void main(String... args) throws Exception {
        String startedRegistration = u2f.startRegistration(APP_ID).toJson();
        System.out.println("Registration data:");
        System.out.println(startedRegistration);

        System.out.println();
        System.out.println("Enter token response:");

        String json = scan.nextLine();
        RegisterResponse registerResponse = RegisterResponse.fromJson(json);
        registerResponse.getClientData().getChallenge();
        DeviceRegistration deviceRegistration = u2f.finishRegistration(
                RegisterRequest.fromJson(startedRegistration),
                registerResponse,
                TRUSTED_DOMAINS
        );

        System.out.println(deviceRegistration);

        String startedAuthentication = u2f.startAuthentication(APP_ID, deviceRegistration).toJson();
        System.out.println("Authentication data:");
        System.out.println(startedAuthentication);

        System.out.println();
        System.out.println("Enter token response:");

        u2f.finishAuthentication(
                AuthenticateRequest.fromJson(startedAuthentication),
                AuthenticateResponse.fromJson(scan.nextLine()),
                deviceRegistration,
                TRUSTED_DOMAINS
        );
        System.out.println("Device counter: " + deviceRegistration.getCounter());
    }
}
