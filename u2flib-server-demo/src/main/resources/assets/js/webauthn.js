(function(root, factory) {
  if (typeof define === 'function' && define.amd) {
    define(['base64url'], factory);
  } else if (typeof module === 'object' && module.exports) {
    module.exports = factory(require('base64url'));
  } else {
    root.webauthn = factory(root.base64url);
  }
})(this, function(base64url) {

  /** Turn a PublicKeyCredential object into a plain object with base64url encoded binary values */
  function responseToObject(response) {
    if (response instanceof PublicKeyCredential) {
      if (response.response instanceof AuthenticatorAttestationResponse) {
        return {
          id: response.id,
          rawId: base64url.fromByteArray(response.rawId),
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
    responseToObject: responseToObject,
  };

});
