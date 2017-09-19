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

    <#list messages>
      <#items as item>
        <p>${item}</p>
      </#items>
    </#list>

    <#include "/demo/view/navigation.ftl">

  </div>
</div>
</body>
</html>
