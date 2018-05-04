#!/bin/bash

# Exit on error
set -e

SSH() {
  ssh webauthn.yubicodemo.com "$@"
}


SSH git -C /home/emlun/java-webauthn-server checkout tmp

git push --force demo webauthn-demo-deploy

SSH git -C /home/emlun/java-webauthn-server checkout webauthn-demo-deploy

SSH /home/emlun/java-webauthn-server/webauthn-server-demo/deploy.sh
