package com.yubico.webauthn.benchmark;

import com.yubico.webauthn.AssertionResult;
import com.yubico.webauthn.FinishAssertionOptions;
import com.yubico.webauthn.FinishRegistrationOptions;
import com.yubico.webauthn.RegisteredCredential;
import com.yubico.webauthn.RegistrationResult;
import com.yubico.webauthn.RegistrationTestData;
import com.yubico.webauthn.RegistrationTestData.Packed$;
import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.exception.AssertionFailedException;
import com.yubico.webauthn.exception.RegistrationFailedException;
import com.yubico.webauthn.test.Helpers.CredentialRepository$;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.infra.Blackhole;

public class RelyingPartyBenchmark {

  @State(Scope.Benchmark)
  public static class RegistrationState {
    public final RegistrationTestData testData = Packed$.MODULE$.BasicAttestationEdDsa();

    public final RelyingParty rp =
        RelyingParty.builder()
            .identity(testData.rpId())
            .credentialRepository(CredentialRepository$.MODULE$.empty())
            .build();

    public final FinishRegistrationOptions fro =
        FinishRegistrationOptions.builder()
            .request(testData.request())
            .response(testData.response())
            .build();
  }

  @State(Scope.Benchmark)
  public static class AssertionState {
    public final RegistrationTestData testData = Packed$.MODULE$.BasicAttestationEdDsa();

    public final RelyingParty rp =
        RelyingParty.builder()
            .identity(testData.rpId())
            .credentialRepository(
                CredentialRepository$.MODULE$.withUser(
                    testData.userId(),
                    RegisteredCredential.builder()
                        .credentialId(testData.response().getId())
                        .userHandle(testData.userId().getId())
                        .publicKeyCose(
                            testData
                                .response()
                                .getResponse()
                                .getParsedAuthenticatorData()
                                .getAttestedCredentialData()
                                .get()
                                .getCredentialPublicKey())
                        .build()))
            .build();

    public final FinishAssertionOptions fao =
        FinishAssertionOptions.builder()
            .request(testData.assertion().get().request())
            .response(testData.assertion().get().response())
            .build();
  }

  @Benchmark
  public void finishRegistration(Blackhole bh, RegistrationState state)
      throws RegistrationFailedException {
    final RegistrationResult result = state.rp.finishRegistration(state.fro);
    bh.consume(result.getKeyId());
    bh.consume(result.isBackupEligible());
    bh.consume(result.isBackedUp());
    bh.consume(result.getSignatureCount());
    bh.consume(result.getAaguid());
    bh.consume(result.getPublicKeyCose());
    bh.consume(result.getAuthenticatorExtensionOutputs());
  }

  @Benchmark
  public void finishAssertion(Blackhole bh, AssertionState state) throws AssertionFailedException {
    final AssertionResult result = state.rp.finishAssertion(state.fao);
    bh.consume(result.isBackupEligible());
    bh.consume(result.isBackedUp());
    bh.consume(result.getSignatureCount());
    bh.consume(result.getAuthenticatorExtensionOutputs());
    bh.consume(result.getCredential().getCredentialId());
  }
}
