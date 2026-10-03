# PingR

PingR finds the root cause when a site or API fails. It probes a URL from the device (DNS, TLS expiry, HTTP status, TTFB), then correlates a failure with
Sentry issues and recent GitHub commits. Tap **Demo** to explore the UI without credentials.

## Run
1. Install Flutter (3.19+). In this folder run: `flutter create . --project-name pingr --platforms=android,ios,macos,windows,linux`
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

## What it detects
Sentry and GitHub are optional. Everything below works without any account.

- DNS: failures, localhost/private IPs, slow lookups, parked domains.
- Network: every IP behind the name is tested separately (finds one dead server), refused/timed-out/reset connections, captive portals.
- TLS: expired, wrong hostname, self-signed, incomplete chain, protocol mismatch, expiring soon, clock problems.
- HTTP: full status table, Cloudflare 52x/10xx, AWS/Vercel/Heroku/Cloud Run/Railway/Azure errors, nginx/Envoy/HAProxy/Apache/Varnish messages, framework crash pages, database and pool errors, WAF/bot blocks, maintenance and default pages.
- Behaviour: 3 requests to catch intermittent failures, /, /health, /healthz comparison to tell one broken route from a dead site, truncated responses, invalid JSON, HTML where JSON was expected, redirect loops.
- Page JS check: script errors, failed resources, failed fetch/XHR calls, CSP blocks, blank pages.
A "failing layer" verdict is picked from the findings. Copy report exports everything as text.

## How the root cause is found
PingR does not stop at the first error text. It scores a pool of 250+ candidate causes against all the evidence at once:

- 60+ structural causes (DNS, each network path, TLS, proxy, app crash, overload, route bug, slow dependency, bad instance, bad deploy and more), each with weighted evidence for and against.
- 250+ response-body signatures for databases, runtimes, hosting platforms, proxies and firewalls.
- Cross-checks that separate look-alike causes: every IP is asked directly (finds one bad server), the URL is retried with a browser user agent (finds bot blocks), and the www/apex counterpart is compared.
- Independent signals in the same layer reinforce each other; contradicting evidence lowers a cause.
- The result shows the top cause with its percentage, the evidence for and against, other candidates, and what was ruled out.
