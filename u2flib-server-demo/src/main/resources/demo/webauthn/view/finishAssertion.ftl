<html>
<head>
<meta charset="utf-8"/>
<title>Java WebAuthn Demo</title>

<script>

window.onload = function() {
  document.getElementById("request").innerHTML = JSON.stringify(${requestJson}, false, 2);
  document.getElementById("response").innerHTML = JSON.stringify(${responseJson}, false, 2);
}
</script>

</head>
<body>

    <p>Successfully authenticated!</p>

    <h3> Request </h3>
    <pre id="request">${requestJson}</pre>

    <h3> Response </h3>
    <pre id="response">${responseJson}</pre>

    <#include "/demo/view/navigation.ftl">

</body>
</html>
