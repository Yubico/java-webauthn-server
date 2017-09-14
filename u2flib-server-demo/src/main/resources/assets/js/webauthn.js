(function(root, factory) {
  if (typeof define === 'function' && define.amd) {
    define(['base64url'], factory);
  } else if (typeof module === 'object' && module.exports) {
    module.exports = factory(require('base64url'));
  } else {
    root.webauthn = factory(root.base64url);
  }
})(this, function(base64url) {

  /**
   * Create a WebAuthn credential.
   *
   * @param request: object - A MakePublicKeyCredentialOptions object, except
   *   where binary values are base64url encoded strings instead of byte arrays
   *
   * @return the Promise returned by `navigator.credentials.create`
   */
  function createCredential(request) {
    var makePublicKeyCredentialOptions = Object.assign(
      {},
      request,
      {
        challenge: base64url.toByteArray(request.challenge),
        excludeCredentials: request.excludeCredentials.map(function(credential) {
          return Object.assign({}, credential, {
            id: base64url.toByteArray(credential.id),
          });
        }),
        timeout: 10000,
      }
    );

    return navigator.credentials.create({
      publicKey: makePublicKeyCredentialOptions,
    });
  }

  /** Turn a PublicKeyCredential object into a plain object with base64url encoded binary values */
  function responseToObject(response) {
    if (response instanceof PublicKeyCredential) {
      if (response.response instanceof AuthenticatorAttestationResponse) {
        return {
          id: response.id,
          response: {
            attestationObject: base64url.fromByteArray(response.response.attestationObject),
            clientDataJSON: base64url.fromByteArray(response.response.clientDataJSON),
          },
        };
      } else if (response.response instanceof AuthenticatorAssertionResponse) {
        throw new Error("Not implemented.");
      } else {
        throw new Error("Argument.response must be an AuthenticatorAttestationResponse or AuthenticatorAssertionResponse, was: " + (typeof response.response));
      }
    } else {
      throw new Error("Argument must be a PublicKeyCredential, was: " + (typeof response));
    }
  }

  return {
    createCredential: createCredential,
    responseToObject: responseToObject,
  };

});
