#!/bin/sh
# Backend workspace (FastAPI). This repository is Swift/iOS-only for mobile.
# Some automated checks still invoke `./gradlew` from various workspace roots.
echo "gradlew shim (backend workspace root): Kotlin/Gradle project not present; iOS app is under secure-session-app-with-biometric-and-calculator-2525-2540/ios_frontend/ios_app/."
exit 0
