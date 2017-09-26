<html>
<head>
  <meta charset="utf-8"/>
  <title>WebAuthn Demo</title>
  <link href="/css/fonts.css" rel="stylesheet" />
  <link href="/css/bootstrap.min.css" rel="stylesheet" media="screen"/>
  <link href="/css/bootstrap-responsive.min.css" rel="stylesheet"/>
  <link href="/css/bootstrap-yubico.css" rel="stylesheet"/>

<script src="/lib/base64js/base64js-1.2.0.min.js"></script>
<script src="/js/base64url.js"></script>
<script src="/js/webauthn.js"></script>

<script>

function submitResponse(requestId, response) {
  var form = document.getElementById('form');
  var responseField = document.getElementById('response');
  responseField.value = JSON.stringify({
    requestId: requestId,
    credential: webauthn.addJacksonDeserializationHints(webauthn.responseToObject(response)),
  });
  form.submit();
}

window.onload = function() {
  var request = ${requestJson};
  console.log('onload', request);
  document.getElementById("request").innerHTML = JSON.stringify(request, false, 2);

  webauthn.createCredential(request.makePublicKeyCredentialOptions)
    .then(function(response) {
      console.log('Response:', response);
      console.log('Response:', JSON.stringify(webauthn.responseToObject(response)));
      window.result = response;
      return response;
    }).then(function(response) {
      submitResponse("${requestId}", response);
    }).catch(function(err) {
      console.error('Failed:', err.name, err.message, err);

      if (err.name === 'NotAllowedError'
        && request.makePublicKeyCredentialOptions.excludeCredentials
        && request.makePublicKeyCredentialOptions.excludeCredentials.length > 0
      ) {
        document.getElementById('messages').innerHTML += '<p>Credential creation failed, probably because an already registered credential is avaiable.</p>';
      } else {
        document.getElementById('messages').innerHTML += '<p>Credential creation failed for an unknown reason.</p>';
      }
    })
  ;

  return false;
}

</script>

</head>
<body>

<div class="base">
  <div class="content">

    <div class="header-logo visible-desktop">
      <a href="https://www.yubico.com/" title="Yubico">
        <img src="/img/yubico-logo.png"/>
      </a>
    </div>

    <h1> Test your WebAuthn device </h1>

    <p>Requesting credential creation!</p>
    <p>Your browser or authenticator may prompt you for confirmation. If your authenticator is blinking, touch it now.</p>

    <form method="POST" action="finishRegistration" id="form" onsubmit="return false">
      <input type="hidden" name="response" id="response"/>
    </form>

    <div id="messages">
    </div>

    <p> Request ID: <pre>${requestId}</pre></p>

    <p> Request: </p>
    <pre id="request">${requestJson}</pre>

    <#include "/demo/view/navigation.ftl">

  </div>
</div>

</body>
</html>
