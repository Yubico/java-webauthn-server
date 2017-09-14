<html>
<head>
<meta charset="utf-8"/>

<title>Java WebAuthn Demo</title>

<script src="/lib/base64js/base64js-1.2.0.min.js"></script>
<script src="/js/base64url.js"></script>

<script>

function translateForFirefoxNightly57_0a1(request) {
  return Object.assign({}, request, {
    parameters: request.parameters.map(function(item) {
      return Object.assign({}, item, {
        algorithm: item.alg === -7 ? 'ES256' : item.alg,
      });
    }),
  });
}

function createCredential(request) {
  console.log('createCredential', request);
  var challengeBytes = base64url.toByteArray(request.challenge);

  console.log('challenge', challengeBytes);

  console.log('request', translateForFirefoxNightly57_0a1(request));

  var makePublicKeyCredentialOptions = Object.assign(
    {},
    request,
    {
      challenge: challengeBytes,
      excludeCredentials: request.excludeCredentials.map(function(credential) {
        return Object.assign({}, credential, {
          id: base64url.toByteArray(credential.id),
        });
      }),
      timeout: 10000,
    }
  );

  console.log('makePublicKeyCredentialOptions', makePublicKeyCredentialOptions);

  return navigator.credentials.create({
    publicKey: translateForFirefoxNightly57_0a1(makePublicKeyCredentialOptions),
  });
}

function addJacksonDeserializationHints(response) {
  if (response.response.attestationObject) {
    return Object.assign({}, response, {
      '@jackson_type': 'com.yubico.webauthn.data.impl.PublicKeyCredential',
      response: Object.assign({}, response.response, {
        '@jackson_type': 'com.yubico.webauthn.data.impl.AuthenticatorAttestationResponse',
      }),
    });
  } else {
    return Object.assign({}, response, {
      '@jackson_type': 'com.yubico.webauthn.data.impl.PublicKeyCredential',
      response: Object.assign({}, response.response, {
        '@jackson_type': 'com.yubico.webauthn.data.impl.AuthenticatorAssertionResponse',
      }),
    });
  }
}

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

function submitResponse(requestId, response) {
  var form = document.getElementById('form');
  var responseField = document.getElementById('response');
  responseField.value = JSON.stringify({
    requestId: requestId,
    credential: addJacksonDeserializationHints(responseToObject(response)),
  });
  form.submit();
}

window.onload = function() {
  var request = ${requestJson};
  console.log('onload', request);
  document.getElementById("request").innerHTML = JSON.stringify(request, false, 2);

  createCredential(request.makePublicKeyCredentialOptions)
    .then(function(response) {
      console.log('Response:', response);
      console.log('Response:', JSON.stringify(responseToObject(response)));
      window.result = response;
      return response;
    }).then(function(response) {
      submitResponse("${requestId}", response);
    }).catch(function(err) {
      console.error('Failed:', err.name, err.message, err);
    })
  ;

  return false;
}

</script>

</head>
<body>

  <p>Please wait...</p>

  <form method="POST" action="finishRegistration" id="form" onsubmit="return false">
    <input type="hidden" name="response" id="response"/>
  </form>

  <p> Request ID: <pre>${requestId}</pre></p>

  <p> Request: </p>
  <pre id="request">${requestJson}</pre>

  <#include "/demo/view/navigation.ftl">

</body>
</html>
