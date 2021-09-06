/**
 * This package makes up the public API of the webauthn-server-core library.
 *
 * <p>The main entry point is the {@link com.yubico.webauthn.RelyingParty} class. It provides
 * methods for generating inputs to the <code>navigator.credentials.create()</code> and <code>
 * navigator.credentials.get()</code> methods and for processing the return values from those same
 * methods. In order to do this, the {@link com.yubico.webauthn.RelyingParty} needs an instance of
 * the {@link com.yubico.webauthn.CredentialRepository} interface to use for looking up the
 * credential IDs and public keys registered to each user, among other things.
 *
 * <h2>What this library does not do</h2>
 *
 * <p>This library has no concept of accounts, sessions, permissions or identity federation - it
 * only deals with executing the Web Authentication <i>authentication mechanism</i>. Sessions,
 * account management and other higher level concepts can make use of this authentication mechanism,
 * but the authentication mechanism alone does not make a security system.
 *
 * <h2>Usage overview</h2>
 *
 * <p>At its core, the library provides four operations:
 *
 * <ul>
 *   <li>Initiate a registration operation given a user and some settings for the credential to be
 *       created
 *   <li>Finish a registration operation given the initiation request and the authenticator response
 *   <li>Initiate an authentication operation given a username
 *   <li>Finish an authentication operation given the initiation request and the authenticator
 *       response
 * </ul>
 *
 * <p>The "start" methods return request objects containing the parameters to be used in the call to
 * <code>navigator.credentials.create()</code> or <code>navigator.credentials.get()</code>, and the
 * "finish" methods expect a pair of such a request object and the response object returned from the
 * browser. The library itself is stateless; once constructed, a {@link
 * com.yubico.webauthn.RelyingParty} instance never modifies its fields, and the "finish" methods
 * return plain object representations of the results. These methods perform all the verification
 * logic specified by Web Authentication, but it is your responsibility as the library user to store
 * pending requests and act upon the returned results - including enforcing policies and updating
 * databases.
 *
 * <h3>Data classes and builders</h3>
 *
 * <p>Logic classes as well as data classes in this library are all immutable, and provide <a
 * href="https://en.wikipedia.org/wiki/Builder_pattern">builders</a> for their construction. Most
 * builders have required parameters, which is encoded in the type system - the <code>build()</code>
 * method will be made available only once all required parameters have been set. The data classes
 * also each have a <code>toBuilder()</code> method which can be used to create a modified copy of
 * the instance.
 *
 * <h2>Instantiating the library</h2>
 *
 * <p>The main entry point to the library is the {@link com.yubico.webauthn.RelyingParty} class,
 * which can be instantiated via its {@link com.yubico.webauthn.RelyingParty#builder() builder}.
 * Refer to the {@link com.yubico.webauthn.RelyingParty.RelyingPartyBuilder} documentation for
 * descriptions of the parameters. Of particular note is the {@link
 * com.yubico.webauthn.RelyingParty.RelyingPartyBuilder#credentialRepository(com.yubico.webauthn.CredentialRepository)
 * credentialRepository} parameter, which takes an application-specific database adapter to use for
 * looking up users' credentials. You'll need to implement the {@link
 * com.yubico.webauthn.CredentialRepository} interface with your own database access logic.
 *
 * <p>Like all other classes in the library, {@link com.yubico.webauthn.RelyingParty} is stateless
 * and therefore thread safe.
 *
 * <h2>Registration</h2>
 *
 * <p>To initiate a registration operation, construct a {@link
 * com.yubico.webauthn.StartRegistrationOptions} instance using its {@link
 * com.yubico.webauthn.StartRegistrationOptions#builder() builder} and pass that into {@link
 * com.yubico.webauthn.RelyingParty#startRegistration(StartRegistrationOptions)}. The only required
 * parameter is a {@link com.yubico.webauthn.data.UserIdentity} describing the user for which to
 * create a credential. One noteworthy part of {@link com.yubico.webauthn.data.UserIdentity} is the
 * {@link com.yubico.webauthn.data.UserIdentity#getId() id} field, containing the <a
 * href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#user-handle">user handle</a> for the
 * user. This should be a stable, unique identifier for the user - equivalent to a username, in most
 * cases. However, due to <a
 * href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-user-handle-privacy">privacy
 * considerations</a> it is recommended to set the user handle to a random byte array rather than,
 * say, the username encoded in UTF-8.
 *
 * <p>The {@link com.yubico.webauthn.RelyingParty#startRegistration(StartRegistrationOptions)
 * startRegistration} method returns a {@link
 * com.yubico.webauthn.data.PublicKeyCredentialCreationOptions} which can be serialized to JSON and
 * passed as the <code>publicKey</code> argument to <code>navigator.credentials.create()</code>. You
 * can use the {@link com.yubico.webauthn.data.PublicKeyCredentialCreationOptions#toBuilder()
 * toBuilder()} method to make any modifications you need. You should store this in temporary
 * storage so that it can later be passed as an argument to {@link
 * com.yubico.webauthn.RelyingParty#finishRegistration(FinishRegistrationOptions)}.
 *
 * <p>After receiving the response from the client, construct a {@link
 * com.yubico.webauthn.data.PublicKeyCredential}&lt;{@link
 * com.yubico.webauthn.data.AuthenticatorAttestationResponse}, {@link
 * com.yubico.webauthn.data.ClientRegistrationExtensionOutputs}&gt; from the response and wrap that
 * in a {@link com.yubico.webauthn.FinishRegistrationOptions} along with the {@link
 * com.yubico.webauthn.data.PublicKeyCredentialCreationOptions} used to initiate the request. Pass
 * that as the argument to {@link
 * com.yubico.webauthn.RelyingParty#finishRegistration(FinishRegistrationOptions)}, which will
 * return a {@link com.yubico.webauthn.RegistrationResult} if successful and throw an exception if
 * not. Regardless of whether it succeeds, you should remove the {@link
 * com.yubico.webauthn.data.PublicKeyCredentialCreationOptions} from the pending requests storage to
 * prevent retries.
 *
 * <p>Finally, use the {@link com.yubico.webauthn.RegistrationResult} to update any database(s) and
 * take other actions depending on your application's needs. In particular:
 *
 * <ul>
 *   <li>Store the {@link com.yubico.webauthn.RegistrationResult#getKeyId() keyId} and {@link
 *       com.yubico.webauthn.RegistrationResult#getPublicKeyCose() publicKeyCose} as a new
 *       credential for the user. The {@link com.yubico.webauthn.CredentialRepository} will need to
 *       look these up for authentication.
 *   <li>Inspect the {@link com.yubico.webauthn.RegistrationResult#getWarnings() warnings} - ideally
 *       there should of course be none.
 *   <li>If you care about authenticator attestation, use the {@link
 *       com.yubico.webauthn.RegistrationResult#isAttestationTrusted() attestationTrusted}, {@link
 *       com.yubico.webauthn.RegistrationResult#getAttestationType() attestationType} and {@link
 *       com.yubico.webauthn.RegistrationResult#getAttestationMetadata() attestationMetadata} fields
 *       to enforce your attestation policy.
 *   <li>If you care about authenticator attestation, it is recommended to also store the raw {@link
 *       com.yubico.webauthn.data.AuthenticatorAttestationResponse#getAttestationObject()
 *       attestation object} as part of the credential. This enables you to retroactively inspect
 *       credential attestations in response to policy changes and/or compromised authenticators.
 * </ul>
 *
 * <h2>Authentication</h2>
 *
 * <p>Authentication works much like registration, except less complex because of the fewer
 * parameters and the absence of authenticator attestation complications.
 *
 * <p>To initiate an authentication operation, call {@link
 * com.yubico.webauthn.RelyingParty#startAssertion(StartAssertionOptions)}. The main parameter you
 * need to set here is the {@link
 * com.yubico.webauthn.StartAssertionOptions.StartAssertionOptionsBuilder#username(java.util.Optional)
 * username} of the user to authenticate, but even this parameter is optional. If the username is
 * not set, then the {@link
 * com.yubico.webauthn.data.PublicKeyCredentialRequestOptions#getAllowCredentials()
 * allowCredentials} parameter will not be set. This which means the user must use a <a
 * href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#client-side-discoverable-public-key-credential-source">client-side-resident
 * credential</a> to authenticate; also known as "first-factor authentication". This use case has
 * both advantages and disadvantages; see the Web Authentication specification for an extended
 * discussion of this.
 *
 * <p>The {@link com.yubico.webauthn.RelyingParty#startAssertion(StartAssertionOptions)
 * startAssertion} method returns an {@link com.yubico.webauthn.AssertionRequest} containing the
 * username, if any, and a {@link com.yubico.webauthn.data.PublicKeyCredentialRequestOptions}
 * instance which can be serialized to JSON and passed as the <code>publicKey</code> argument to
 * <code>navigator.credentials.get()</code>. Again, store the {@link
 * com.yubico.webauthn.AssertionRequest} in temporary storage so it can be passed as an argument to
 * {@link
 * com.yubico.webauthn.RelyingParty#finishAssertion(com.yubico.webauthn.FinishAssertionOptions)}.
 *
 * <p>After receiving the response from the client, construct a {@link
 * com.yubico.webauthn.data.PublicKeyCredential}&lt;{@link
 * com.yubico.webauthn.data.AuthenticatorAssertionResponse}, {@link
 * com.yubico.webauthn.data.ClientAssertionExtensionOutputs}&gt; from the response and wrap that in
 * a {@link com.yubico.webauthn.FinishAssertionOptions} along with the {@link
 * com.yubico.webauthn.AssertionRequest} used to initiate the request. Pass that as the argument to
 * {@link
 * com.yubico.webauthn.RelyingParty#finishAssertion(com.yubico.webauthn.FinishAssertionOptions)},
 * which will return an {@link com.yubico.webauthn.AssertionResult} if successful and throw an
 * exception if not. Regardless of whether it succeeds, you should remove the {@link
 * com.yubico.webauthn.AssertionRequest} from the pending requests storage to prevent retries.
 *
 * <p>Finally, use the {@link com.yubico.webauthn.AssertionResult} to update any database(s) and
 * take other actions depending on your application's needs. In particular:
 *
 * <ul>
 *   <li>Use the {@link com.yubico.webauthn.AssertionResult#getUsername() username} and/or {@link
 *       com.yubico.webauthn.AssertionResult#getUserHandle() userHandle} results to initiate a user
 *       session.
 *   <li>Update the stored signature count for the credential (identified by the {@link
 *       com.yubico.webauthn.AssertionResult#getCredentialId() credentialId} result) to equal the
 *       value returned in the {@link com.yubico.webauthn.AssertionResult#getSignatureCount()
 *       signatureCount} result.
 *   <li>Inspect the {@link com.yubico.webauthn.RegistrationResult#getWarnings() warnings} - ideally
 *       there should of course be none.
 * </ul>
 */
package com.yubico.webauthn;
