package com.yubico.u2f;

import com.google.common.collect.ImmutableSet;
import com.yubico.u2f.server.U2F;
import com.yubico.u2f.server.data.Device;
import com.yubico.u2f.server.messages.StartedAuthentication;
import com.yubico.u2f.server.messages.StartedRegistration;

import java.util.Scanner;

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
    StartedRegistration startedRegistration = U2F.startRegistration(APP_ID, TRUSTED_DOMAINS);
    System.out.println("Registration data:");
    System.out.println(startedRegistration.json());

    System.out.println();
    System.out.println("Enter token response:");

    Device device = startedRegistration.finish(scan.nextLine());

    System.out.println(device);

    StartedAuthentication startedAuthentication = U2F.startAuthentication(APP_ID, TRUSTED_DOMAINS, device);
    System.out.println("Authentication data:");
    System.out.println(startedAuthentication.json());

    System.out.println();
    System.out.println("Enter token response:");

    int deviceCounter = startedAuthentication.finish(scan.nextLine(), device);
    System.out.println("Device counter: " + deviceCounter);
  }
}
