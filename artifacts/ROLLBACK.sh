#!/usr/bin/env bash
# Rollback the Phantom-Shield client patches (restore pristine baselines).
set -e
cp "D:/Project/OpenPhantomShield-main/verify-server/artifacts/Internals.java.baseline" "D:/Project/OpenPhantomShield-main/phantomshield-internals/src/main/java/tech/skidonion/verification/utils/Internals.java"
cp "D:/Project/OpenPhantomShield-main/verify-server/artifacts/NativeObfuscation.java.baseline" "D:/Project/OpenPhantomShield-main/phantomshield-obfuscator/src/main/java/tech/skidonion/obfuscator/transformer/impl/NativeObfuscation.java"
echo "restored 2 files"
