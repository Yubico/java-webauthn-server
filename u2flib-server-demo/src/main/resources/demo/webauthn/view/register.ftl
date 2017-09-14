<html>
<head>
<meta charset="utf-8"/>

<title>Java WebAuthn Demo</title>

<script src="/lib/base64js/base64js-1.2.0.min.js"></script>
<script src="/js/base64url.js"></script>
<script src="/js/webauthn.js"></script>

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

function submitResponse(requestId, response) {
  var form = document.getElementById('form');
  var responseField = document.getElementById('response');
  responseField.value = JSON.stringify({
    requestId: requestId,
    credential: addJacksonDeserializationHints(webauthn.responseToObject(response)),
  });
  form.submit();
}

window.onload = function() {
  var request = ${requestJson};
  console.log('onload', request);
  document.getElementById("request").innerHTML = JSON.stringify(request, false, 2);

  webauthn.createCredential(translateForFirefoxNightly57_0a1(request.makePublicKeyCredentialOptions))
    .then(function(response) {
      console.log('Response:', response);
      console.log('Response:', JSON.stringify(webauthn.responseToObject(response)));
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
