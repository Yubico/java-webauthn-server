#!/bin/bash

# Exit on error
set -e

SSH() {
  ssh webauthn.yubicodemo.com "$@"
}


SSH git -C /home/emlun/java-u2flib-server checkout tmp

git push --force demo webauthn-demo-deploy

SSH git -C /home/emlun/java-u2flib-server checkout webauthn-demo-deploy

SSH /home/emlun/java-u2flib-server/webauthn-server-demo/deploy.sh
