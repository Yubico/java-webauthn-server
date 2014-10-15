package com.yubico.u2f;

import com.google.common.collect.ImmutableSet;
import com.yubico.u2f.data.Device;
import com.yubico.u2f.data.messages.AuthenticateResponse;
import com.yubico.u2f.data.messages.RegisterResponse;
import com.yubico.u2f.data.messages.StartedAuthentication;
import com.yubico.u2f.data.messages.StartedRegistration;
import org.junit.Ignore;

import java.util.Scanner;

@Ignore("Includes manual steps")
public class SystemTest {

  public static final ImmutableSet<String> TRUSTED_DOMAINS = ImmutableSet.of("http://example.com");
  public static final String APP_ID = "my-app";
  private static Scanner scan = new Scanner(System.in);

  /*
    For manual testing with physical keys. Can e.g. be combined with these libu2f-host commands:

      u2f-host -aregister -o http://example.com
      u2f-host -aauthenticate -o http://example.com
   */
  public static void main(String... args) throws Exception {
    String startedRegistration = U2F.startRegistration(APP_ID).toJson();
    System.out.println("Registration data:");
    System.out.println(startedRegistration);

    System.out.println();
    System.out.println("Enter token response:");

    String json = scan.nextLine();
    RegisterResponse registerResponse = RegisterResponse.fromJson(json);
    registerResponse.getClientData().getChallenge();
    Device device = U2F.finishRegistration(
            StartedRegistration.fromJson(startedRegistration),
            registerResponse,
            TRUSTED_DOMAINS
    );


    System.out.println(device);

    String startedAuthentication = U2F.startAuthentication(APP_ID, device).toJson();
    System.out.println("Authentication data:");
    System.out.println(startedAuthentication);

    System.out.println();
    System.out.println("Enter token response:");

    int deviceCounter = U2F.finishAuthentication(
            StartedAuthentication.fromJson(startedAuthentication),
            AuthenticateResponse.fromJson(scan.nextLine()),
            device,
            TRUSTED_DOMAINS
    );
    System.out.println("Device counter: " + deviceCounter);
  }
}
