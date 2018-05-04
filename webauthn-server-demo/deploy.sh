#!/bin/bash

# Exit on error
set -e


cd /home/emlun/java-webauthn-server/webauthn-server-demo

../gradlew war

cp build/libs/webauthn-server-demo-0.18.0.war docker/webauthn-server-demo.war

docker build docker/ -t webauthn-server-demo-local

docker create -p 443:8443 -v /home/emlun/private:/usr/local/tomcat/conf/ssl:ro --name webauthn-demo-new webauthn-server-demo-local
docker stop webauthn-demo
docker start webauthn-demo-new
docker rm -v webauthn-demo-old
docker rename webauthn-demo webauthn-demo-old
docker rename webauthn-demo-new webauthn-demo
