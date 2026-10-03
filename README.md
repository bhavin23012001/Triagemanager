# Triage Agent (Flutter)

Probes a URL from the device (DNS, TLS expiry, HTTP status, TTFB), then correlates a failure with
Sentry issues and recent GitHub commits. Tap **Demo** to explore the UI without credentials.

## Run
1. Install Flutter (3.19+). In this folder run: `flutter create . --project-name triage_agent --platforms=android,ios,macos,windows,linux`
   (this generates the platform folders; it will not overwrite `lib/` or `pubspec.yaml`)
2. `flutter pub get`
3. `flutter run`  |  Android APK: `flutter build apk --release`

## Platform notes
- Android: add `<uses-permission android:name="android.permission.INTERNET"/>` to `android/app/src/main/AndroidManifest.xml`.
- macOS: add `com.apple.security.network.client` = true to both `macos/Runner/*.entitlements` files.
- Web is not supported (uses dart:io sockets for DNS/TLS).

## Integrations (Settings screen)
- Sentry: auth token with `event:read` + `project:read`, org slug, project slug.
- GitHub: `owner/repo`; token only for private repos (read-only).
- Tokens are stored with shared_preferences (plain). Move to flutter_secure_storage before production.

## Limits
The score is a timing-overlap heuristic, not proof. Public probing cannot see server internals; that
is why the Sentry and GitHub integrations exist.
