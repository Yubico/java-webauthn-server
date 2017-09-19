<html>
<head>
<meta charset="utf-8"/>
<title>WebAuthn Demo</title>
<link href="/css/fonts.css" rel="stylesheet" />
<link href="/css/bootstrap.min.css" rel="stylesheet" media="screen"/>
<link href="/css/bootstrap-responsive.min.css" rel="stylesheet"/>
<link href="/css/bootstrap-yubico.css" rel="stylesheet"/>

<script>

window.onload = function() {
  const preElements = document.getElementsByTagName("pre");
  for (var i = 0; i < preElements.length; ++i) {
    preElements[i].innerHTML = JSON.stringify(JSON.parse(preElements[i].innerHTML), false, 2);
  }
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

    <p>Successfully authenticated!</p>

    <h3> Your registered credentials: </h3>

    <#list registrations>
      <table>

        <thead>
          <tr>
            <th> Nickname </th>
            <th> Registered </th>
            <th> Actions </th>
            <th> Details </th>
          </tr>
        </thead>

        <tbody>
          <#items as registration>
            <tr>
              <td> ${registration.getCredentialNickname()} </td>
              <td> ${registration.getRegistrationTime()} </td>
              <td>

                <form action="deregister" method="post">
                  <input type="hidden" name="username" value="${registration.getUsername()}"/>
                  <input type="hidden" name="credentialId" value="${registration.getRegistration().keyId().idBase64()}"/>
                  <button type="submit"> Deregister </button>
                </form>

              </td>

              <td>
                <pre>${registration.toJson()}</pre>
              </td>
            </tr>
          </#items>
        </tbody>
      </table>
    </#list>


    <h3> Request </h3>
    <pre id="request">${requestJson}</pre>

    <h3> Response </h3>
    <p>Properties prefixed with <code>_</code> are parsed versions of the corresponding Base64 encoded binary blob.
    Properties prefixed with <code>@</code> are implementation-specific deserialization hints.</p>
    <pre id="response">${responseJson}</pre>

    <#include "/demo/view/navigation.ftl">

  </div>
</div>

</body>
</html>
