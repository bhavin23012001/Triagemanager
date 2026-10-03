import 'dart:io';
import 'inspector.dart';
import 'probe.dart';
import 'signatures.dart';

/// A possible root cause: what is wrong, where, why it matters, and how to fix it.
class Cause {
  const Cause(this.id, this.title, this.layer, this.why, this.fixes);
  final String id;
  final String title;
  final String layer;
  final String why;
  final List<String> fixes;
}

/// A cause that was scored against the evidence.
class RootCause {
  RootCause(this.cause, this.score, this.support, this.against);
  final Cause cause;
  final int score; // 0..100 evidence strength
  final List<String> support;
  final List<String> against;
  int get confidence => score >= 80 ? 2 : (score >= 50 ? 1 : 0);
}

/// Everything the probe learned, as questions the rules can ask.
class Facts {
  Facts(this.p, this.backendScore) : body = p.body.toLowerCase();
  final ProbeResult p;
  final int? backendScore;
  final String body;

  int? get s => p.status;
  bool get is5xx => (s ?? 0) >= 500;
  bool get dnsFail => p.dnsError != null;
  bool get offline => p.deviceOffline;
  bool get invalidUrl => p.dnsError == 'Invalid URL';
  bool get loopback => p.addrs.any((a) => a.isLoopback);
  bool get privateIp => p.addrs.any((a) {
        if (a.type != InternetAddressType.IPv4) return false;
        final b = a.rawAddress;
        return b[0] == 10 || (b[0] == 172 && b[1] >= 16 && b[1] <= 31) || (b[0] == 192 && b[1] == 168);
      });
  int get realIpDown => p.ipErr.entries
      .where((e) => !(e.key.contains(':') && (e.value.contains('unreachable') || e.value.contains('No route'))))
      .length;
  bool get noServer => !dnsFail && p.tcpMs == null && p.ipMs.isNotEmpty && !offline;
  bool get partialDown => p.tcpMs != null && realIpDown > 0;
  String get connErr => (p.httpError ?? (p.ipErr.values.isEmpty ? '' : p.ipErr.values.first)).toLowerCase();
  bool get tlsFail => p.tlsError != null;
  String get tlsE => (p.tlsError ?? '').toLowerCase();
  String get httpE => (p.httpError ?? '').toLowerCase();
  bool get httpTimeout => httpE.contains('timed out after');
  bool get loop => httpE.contains('redirect');
  int? get root => p.companions['/'];
  bool get rootKnown => p.companions.containsKey('/');
  bool get rootOk => root != null && root! < 500;
  bool get rootBad => rootKnown && !rootOk;
  List<int?> get healthCodes => [
        if (p.companions.containsKey('/health')) p.companions['/health'],
        if (p.companions.containsKey('/healthz')) p.companions['/healthz'],
      ];
  bool get healthOk => healthCodes.any((c) => c == 200);
  bool get healthBad => healthCodes.any((c) => c != null && c >= 500);
  int get repN => p.repeats.length;
  int get repBad => p.repeats.where((c) => c == null || c >= 500).length;
  bool get intermittent => repN > 1 && repBad > 0 && repBad < repN;
  bool get consistent => repN > 1 && repBad == repN;
  int get ttfb => p.ttfbMs ?? 0;
  bool get slow => ttfb > 3000;
  bool get verySlow => ttfb >= 5000;
  bool get fast => p.ttfbMs != null && ttfb < 1500;
  bool get failing => is5xx || httpTimeout || p.truncated || p.httpError != null;
  bool get mixedIps {
    final bad = p.ipStatus.values.where((c) => c == null || c >= 500).length;
    final good = p.ipStatus.values.where((c) => c != null && c < 500).length;
    return bad > 0 && good > 0;
  }

  bool has(String t) => body.contains(t);
  bool hdr(String k) => p.headers.containsKey(k);
  String hv(String k) => (p.headers[k] ?? '').toLowerCase();
  bool get cf => p.cdn == 'Cloudflare';
  String get ct => p.contentType ?? '';
}

class _Rule {
  _Rule(this.w, this.note, this.test);
  final int w;
  final String Function(Facts) note;
  final bool Function(Facts) test;
}

class _Def {
  _Def(this.cause, this.rules);
  final Cause cause;
  final List<_Rule> rules;
}

_Rule _r(int w, String note, bool Function(Facts) t) => _Rule(w, (_) => note, t);
_Rule _rd(int w, String Function(Facts) note, bool Function(Facts) t) => _Rule(w, note, t);
_Def _d(String id, String title, String layer, String why, List<String> fixes, List<_Rule> rules) =>
    _Def(Cause(id, title, layer, why, fixes), rules);

String _sec(int ms) => '${(ms / 1000).toStringAsFixed(1)}s';

final List<_Def> _structural = [
  // ---------- Your side, DNS ----------
  _d('offline', 'Your device is offline', 'Your connection', 'The phone could not reach the internet, so this says nothing about the site.',
      ['Check Wi-Fi or mobile data.', 'Scan again on another network.'],
      [_r(95, 'The device could not reach 1.1.1.1 or resolve a test domain', (x) => x.offline)]),
  _d('bad_url', 'The address is not a valid URL', 'DNS', 'The text entered cannot be turned into a web address.',
      ['Enter a full address such as https://example.com/path.'],
      [_r(95, 'The input could not be parsed as a URL', (x) => x.invalidUrl)]),
  _d('dns_missing', 'Domain does not resolve (expired, removed or misspelled)', 'DNS',
      'No DNS answer exists for this name. The domain may have expired, the records may be gone, or the name is mistyped.',
      ['Check the domain has not expired at the registrar.', 'Check the A, AAAA or CNAME records at the DNS provider.', 'Check the nameservers still point at your DNS host.'],
      [
        _rd(75, (x) => 'DNS lookup failed: ${x.p.dnsError}', (x) => x.dnsFail && !x.invalidUrl && !x.offline),
        _r(-60, 'The device itself is offline', (x) => x.offline),
      ]),
  _d('dns_local', 'DNS points to a private or local address', 'DNS',
      'The name resolves to an address no outside client can reach.',
      ['Replace the record with the public IP or load balancer address.', 'Check for split-horizon DNS leaking an internal record.'],
      [
        _rd(85, (x) => 'The name resolves to ${x.p.addrs.map((a) => a.address).join(', ')}', (x) => x.loopback || x.privateIp),
      ]),
  _d('dns_slow', 'Slow DNS resolution', 'DNS', 'The DNS provider took too long to answer.',
      ['Check the DNS provider status.', 'Lower the number of CNAME hops.', 'Use a faster DNS host.'],
      [_rd(55, (x) => 'The lookup took ${x.p.dnsMs}ms', (x) => (x.p.dnsMs ?? 0) > 1000)]),

  // ---------- Network ----------
  _d('port_closed', 'Nothing is listening on the port (service stopped)', 'Network',
      'The server answered but refused the connection: the web server or app process is not running.',
      ['Start the web server or app process.', 'Check it listens on the right port and interface.', 'Check the process did not crash on boot.'],
      [
        _r(80, 'Every address refused the connection', (x) => x.noServer && x.connErr.contains('refused')),
        _r(10, 'The host is up (it actively refused rather than timing out)', (x) => x.noServer && x.connErr.contains('refused')),
      ]),
  _d('fw_drop', 'A firewall or security group is dropping packets', 'Network',
      'Connections time out instead of being refused, which is what a silent firewall rule or dead host looks like.',
      ['Open the port in the security group and host firewall.', 'Check network ACLs and any IP allow-list.', 'Check the server is powered on and reachable.'],
      [
        _r(65, 'Every address timed out on connect', (x) => x.noServer && x.connErr.contains('timed out')),
        _r(-20, 'The device itself may be offline', (x) => x.offline),
      ]),
  _d('no_route', 'No route to the host', 'Network', 'The network path to the server is broken or the host is gone.',
      ['Check the VM or instance exists and has a public address.', 'Check routing tables and the internet gateway.', 'Check the ISP or cloud region for an outage.'],
      [_r(65, 'The connection failed with no route or network unreachable', (x) => x.noServer && (x.connErr.contains('route') || x.connErr.contains('unreachable')))]),
  _d('conn_reset', 'The connection was reset on connect', 'Network', 'Something actively killed the connection: DDoS protection, an IP ban, or a crashing listener.',
      ['Check IP ban lists and rate limiters.', 'Check the listener process for crashes.', 'Try from a different network.'],
      [_r(65, 'The connection was reset by the peer', (x) => x.noServer && x.connErr.contains('reset'))]),
  _d('pool_partial', 'One or more servers behind the name are down', 'Network',
      'The name resolves to several servers and some do not accept connections, so requests fail at random.',
      ['Remove or repair the dead address in DNS or the load balancer.', 'Check that server is running and reachable.', 'Add health checks that drop dead nodes automatically.'],
      [
        _rd(85, (x) => '${x.realIpDown} of ${x.p.ipMs.length} addresses refuse or drop connections', (x) => x.partialDown),
        _r(10, 'Repeated requests gave mixed results', (x) => x.partialDown && x.intermittent),
      ]),
  _d('latency', 'High network latency or packet loss', 'Network', 'Connecting is slow: distance, congestion, or an overloaded host.',
      ['Check packet loss between the client and server.', 'Serve from a closer region or a CDN.', 'Check the host is not saturated.'],
      [_rd(50, (x) => 'TCP connect took ${x.p.tcpMs}ms', (x) => (x.p.tcpMs ?? 0) > 1000)]),
  _d('captive', 'A Wi-Fi login page (captive portal) is in the way', 'Network', 'The network is intercepting traffic until you sign in.',
      ['Open a browser and sign in to the Wi-Fi.', 'Use mobile data instead.'],
      [_r(90, 'The response was HTTP 511', (x) => x.s == 511)]),

  // ---------- TLS ----------
  _d('tls_expired', 'The TLS certificate has expired', 'TLS / certificate', 'Clients refuse the connection because the certificate is past its end date.',
      ['Renew the certificate now.', 'Check that auto-renewal (certbot, ACM, Caddy) is running.', 'Check the renewal DNS or HTTP challenge still works.'],
      [_r(95, 'The TLS handshake reported an expired certificate', (x) => x.tlsE.contains('expired'))]),
  _d('tls_host', 'The certificate does not cover this hostname', 'TLS / certificate', 'The certificate was issued for a different name.',
      ['Reissue the certificate with this hostname.', 'Check the right certificate is bound to this virtual host.', 'Check SNI is configured.'],
      [_r(95, 'The handshake reported a hostname mismatch', (x) => x.tlsE.contains('hostname'))]),
  _d('tls_selfsigned', 'The server uses a self-signed certificate', 'TLS / certificate', 'No trusted authority signed it, so clients reject it.',
      ['Install a certificate from a trusted CA (Let\'s Encrypt is free).'],
      [_r(92, 'The handshake reported a self-signed certificate', (x) => x.tlsE.contains('self-signed'))]),
  _d('tls_chain', 'The certificate chain is incomplete', 'TLS / certificate', 'The server did not send its intermediate certificate.',
      ['Serve the full chain (fullchain.pem), not only the leaf certificate.'],
      [_r(92, 'The handshake reported an untrusted or incomplete chain', (x) => x.tlsE.contains('chain'))]),
  _d('tls_proto', 'TLS versions or ciphers do not overlap', 'TLS / certificate', 'The client and server share no protocol version or cipher.',
      ['Enable TLS 1.2 and 1.3 on the server.', 'Remove obsolete cipher-only configurations.'],
      [_r(88, 'The handshake reported a protocol or version mismatch', (x) => x.tlsE.contains('protocol'))]),
  _d('tls_generic', 'TLS handshake failed', 'TLS / certificate', 'The secure connection could not be established for an unspecified reason.',
      ['Test the endpoint with an SSL checker.', 'Check the proxy terminates TLS on this port.', 'Check the server is not speaking plain HTTP on 443.'],
      [_r(60, 'The TLS handshake failed', (x) => x.tlsE.contains('handshake failed'))]),
  _d('tls_future', 'Certificate is not valid yet (clock problem)', 'TLS / certificate', 'The certificate start date is in the future: a wrong clock on the server or this device.',
      ['Fix the clock on the server (enable NTP).', 'Check this device\'s date and time.'],
      [_r(90, 'The certificate start date is in the future', (x) => x.p.tlsStart != null && x.p.tlsStart!.isAfter(DateTime.now()))]),
  _d('tls_soon', 'The certificate is about to expire', 'TLS / certificate', 'It still works, but it will break soon.',
      ['Renew now and verify auto-renewal.'],
      [
        _rd(55, (x) => 'Only ${x.p.tlsDays} days remain', (x) => x.p.tlsDays != null && x.p.tlsDays! < 14),
        _r(30, 'Fewer than 3 days remain', (x) => x.p.tlsDays != null && x.p.tlsDays! < 3),
      ]),

  // ---------- HTTP and app ----------
  _d('app_down', 'The app process is down or crashed behind the proxy', 'Origin server',
      'A proxy is up but the application behind it is not answering, so every request ends in a gateway error.',
      ['Check the app process is running; restart it.', 'Read the app logs for the crash reason.', 'Check the app listens on the port the proxy expects.', 'Roll back if it started after a deploy.'],
      [
        _rd(45, (x) => 'Gateway-style status ${x.s}', (x) => const [502, 503, 520, 521].contains(x.s)),
        _r(22, 'The site root fails too, so it is not one route', (x) => x.rootBad),
        _r(14, 'All repeated requests failed', (x) => x.consistent),
        _r(10, 'The error came back quickly (a refused or crashed upstream)', (x) => x.is5xx && x.fast),
        _r(-28, 'Failures are intermittent, which points to one bad instance instead', (x) => x.intermittent),
        _r(-30, 'The site root answers fine', (x) => x.rootOk),
      ]),
  _d('overloaded', 'The app is overloaded or out of workers', 'Origin server',
      'Requests queue until the proxy gives up. The app is saturated by traffic, slow work, or too few workers.',
      ['Check CPU, memory and worker/thread usage.', 'Add instances or raise worker counts.', 'Look for a slow endpoint or a traffic spike.', 'Add caching or rate limits in front of expensive routes.'],
      [
        _rd(28, (x) => 'Overload-style status ${x.s}', (x) => const [503, 504, 522, 524].contains(x.s)),
        _rd(22, (x) => 'First byte took ${_sec(x.ttfb)}', (x) => x.slow),
        _r(16, 'Some requests succeed and some fail', (x) => x.intermittent),
        _r(15, 'The server sent a Retry-After header', (x) => x.hdr('retry-after')),
        _r(-20, 'The error is instant, not slow', (x) => x.is5xx && x.fast),
      ]),
  _d('route_bug', 'A bug in this route\'s code', 'Origin server',
      'The server is up and the rest of the site works, but this endpoint throws an unhandled error.',
      ['Read the app logs or Sentry for this route\'s stack trace.', 'Check what changed in this route recently.', 'Reproduce with the same input locally.'],
      [
        _r(32, 'The response is a 500', (x) => x.s == 500),
        _rd(36, (x) => 'The site root answers ${x.root}, so the server is up', (x) => x.is5xx && x.rootOk),
        _r(10, 'It fails quickly, which looks like an exception rather than a wait', (x) => x.is5xx && x.fast),
        _r(8, 'Every repeated request fails the same way', (x) => x.consistent),
        _r(-30, 'It fails slowly, which points to a waiting dependency', (x) => x.verySlow),
      ]),
  _d('dep_slow', 'A slow or hung dependency (database or external API)', 'Database / dependency',
      'This route waits on something slow, then gives up, while the rest of the site answers.',
      ['Find the slowest query this route runs (slow log, APM, EXPLAIN).', 'Check connection pool usage and max connections.', 'Look for locks or long transactions.', 'Check external APIs this route calls.', 'Add query timeouts and indexes.'],
      [
        _rd(32, (x) => 'The request failed after ${_sec(x.ttfb)}', (x) => x.failing && (x.verySlow || x.httpTimeout)),
        _rd(30, (x) => 'The site root answers ${x.root}', (x) => x.failing && x.rootOk),
        _r(14, 'The error is a 5xx rather than a refusal', (x) => x.is5xx),
        _r(-20, 'The root fails too, so this is not only one route', (x) => x.rootBad),
      ]),
  _d('host_outage', 'The whole site is down', 'Origin server', 'Every path fails, so this is a host-wide or upstream outage and not a single bug.',
      ['Check the host, container or platform status page.', 'Check the proxy and the app process.', 'Check for a bad deploy or expired credentials.'],
      [
        _r(52, 'The root URL fails as well', (x) => x.is5xx && x.rootBad),
        _r(14, 'The health endpoints fail too', (x) => x.healthBad),
        _r(10, 'All repeated requests failed', (x) => x.consistent),
      ]),
  _d('bad_instance', 'One server instance is returning errors', 'Origin server', 'The same URL works on some servers and fails on others, so users see random failures.',
      ['Take the failing instance out of rotation.', 'Read its logs and restart or redeploy it.', 'Compare its version and config with a healthy instance.'],
      [
        _r(92, 'Asked directly, some addresses answer and others fail', (x) => x.mixedIps),
        _r(52, 'Some repeated requests succeed and others fail', (x) => x.intermittent),
        _r(-15, 'Every repeated request failed', (x) => x.consistent),
      ]),
  _d('bad_deploy', 'A recent deploy introduced the failure', 'Origin server', 'Backend correlation found a recent commit that overlaps the failure window.',
      ['Compare the suspect commit in the Evidence screen.', 'Roll back the deploy and check if the error stops.', 'Review the diff for the failing route.'],
      [
        _rd(48, (x) => 'Sentry/GitHub correlation score is ${x.backendScore}/100', (x) => (x.backendScore ?? 0) >= 70 && x.failing),
        _rd(26, (x) => 'Sentry/GitHub correlation score is ${x.backendScore}/100', (x) => (x.backendScore ?? 0) >= 50 && (x.backendScore ?? 0) < 70 && x.failing),
      ]),
  _d('health_bad', 'The app reports itself unhealthy', 'Origin server', 'Its own health endpoint fails even though pages may still load, which usually means a broken dependency.',
      ['Read what the health check tests (database, cache, queue).', 'Fix the dependency it reports.', 'Check the load balancer is not routing to unhealthy instances.'],
      [
        _r(55, 'A health endpoint returns 5xx', (x) => x.healthBad),
        _r(10, 'The main page still answers', (x) => x.healthBad && x.rootOk),
      ]),
  _d('hung', 'The app accepted the request but never answered', 'Origin server', 'The connection opens and then nothing comes back: a hung process, deadlock, or exhausted worker pool.',
      ['Check for stuck workers or a deadlock.', 'Restart the process and watch whether it recurs.', 'Take a thread dump or profile while it hangs.'],
      [
        _rd(62, (x) => 'No reply within the timeout (${x.p.httpError})', (x) => x.httpTimeout),
        _r(14, 'The site root fails too', (x) => x.httpTimeout && x.rootBad),
      ]),
  _d('killed', 'The server or a proxy killed the connection', 'Origin server', 'The connection was reset mid-request: a crash, restart, or a proxy limit.',
      ['Check for crashes or restarts at that time.', 'Check proxy timeouts and size limits.', 'Check memory limits (OOM kills).'],
      [_rd(66, (x) => 'The request ended with: ${x.p.httpError}', (x) => x.httpE.contains('reset'))]),
  _d('http_refused', 'The service stopped accepting HTTP connections', 'Origin server', 'The port was open but the request was refused.',
      ['Check the service is running and bound to the right address.'],
      [_r(60, 'The HTTP request was refused', (x) => x.httpE.contains('refused') && x.p.tcpMs != null)]),
  _d('truncated', 'The response was cut off mid-way', 'Proxy / load balancer', 'The connection closed before the whole response arrived: a crash mid-request, a proxy limit, or a timeout.',
      ['Check proxy buffer and timeout settings.', 'Check the app did not crash while streaming.', 'Check for memory limits killing the process.'],
      [_rd(88, (x) => x.p.bodyError ?? 'The connection ended early', (x) => x.p.truncated)]),
  _d('http_proto', 'The server sent an invalid HTTP response', 'Proxy / load balancer', 'Something between you and the app speaks broken HTTP: a proxy bug or a non-HTTP service on this port.',
      ['Check the port really serves HTTP/HTTPS.', 'Check proxy protocol and HTTP/2 settings.'],
      [_r(66, 'The client reported an HTTP protocol error', (x) => x.httpE.contains('protocol error'))]),
  _d('redirect_loop', 'Redirect loop', 'Proxy / load balancer', 'Two rules send the request back and forth: often HTTP/HTTPS, www/apex, or trailing-slash rules fighting.',
      ['List the redirect chain and find the rules that point at each other.', 'Check the proxy sets X-Forwarded-Proto and the app trusts it.', 'Remove duplicate redirect rules from the CDN, proxy and app.'],
      [
        _r(96, 'The client followed too many redirects', (x) => x.loop),
        _rd(30, (x) => 'The chain: ${x.p.redirects.take(3).join(' | ')}', (x) => x.p.redirects.length >= 3),
      ]),
  _d('https_downgrade', 'Redirects send HTTPS users to plain HTTP', 'Proxy / load balancer', 'An app behind a proxy thinks the request is HTTP and redirects to http://.',
      ['Forward X-Forwarded-Proto and make the app trust it.', 'Set the canonical URL to https.'],
      [_r(52, 'A redirect points to http://', (x) => x.p.url.scheme == 'https' && x.p.redirects.any((r) => r.contains('-> http://')))]),
  _d('host_mismatch', 'Only one hostname is broken (www vs apex)', 'Proxy / load balancer', 'The other form of the domain works, so this name\'s record, virtual host or proxy rule is wrong.',
      ['Point both the apex and www records at the same place.', 'Add this hostname to the virtual host or ingress rules.', 'Check the CDN has both names attached.'],
      [_rd(60, (x) => '${x.p.altHost} answers ${x.p.altStatus} while ${x.p.url.host} returns ${x.s}', (x) => x.is5xx && x.p.altStatus != null && x.p.altStatus! < 400)]),
  _d('rate_limit', 'Rate limited', 'Request / auth', 'Too many requests came from this client. This is not an outage.',
      ['Wait for the Retry-After period.', 'Raise or exempt monitoring from the limit.'],
      [
        _r(86, 'The response is HTTP 429', (x) => x.s == 429),
        _r(40, 'x-ratelimit-remaining is 0', (x) => x.p.headers['x-ratelimit-remaining'] == '0'),
        _r(8, 'A Retry-After header was sent', (x) => x.hdr('retry-after')),
      ]),
  _d('bot_block', 'A firewall blocks automated clients (not an outage)', 'Firewall / bot protection',
      'The URL fails for this probe but works for a browser, so real users are probably fine.',
      ['Allow-list your monitoring IP or user agent.', 'Review WAF and bot rules.', 'Test again from another network.'],
      [
        _rd(78, (x) => 'The probe got ${x.s}; a browser user agent got ${x.p.browserStatus}', (x) => x.s != null && x.s! >= 400 && x.p.browserStatus != null && x.p.browserStatus! < 400),
        _r(22, 'Cloudflare sent the 403', (x) => x.cf && x.s == 403),
      ]),
  _d('auth', 'Authentication is required', 'Request / auth', 'The endpoint needs credentials. This is not an outage.',
      ['Send a valid token or log in.', 'Check API gateway auth settings.'],
      [
        _r(82, 'The response is HTTP 401', (x) => x.s == 401),
        _r(30, 'The request redirected to a login page', (x) => x.p.redirects.isNotEmpty && RegExp(r'login|signin|sign-in|auth').hasMatch(x.p.redirects.last)),
      ]),
  _d('forbidden', 'Access is forbidden by permissions or IP rules', 'Request / auth', 'The server understood the request and refused it.',
      ['Check file or route permissions.', 'Check IP allow-lists and WAF rules.'],
      [
        _r(66, 'The response is HTTP 403', (x) => x.s == 403),
        _r(-35, 'A browser user agent gets through, so this is a bot rule instead', (x) => x.p.browserStatus != null && x.p.browserStatus! < 400),
      ]),
  _d('not_found', 'The path does not exist', 'Request / auth', 'The server is up but has no route for this path.',
      ['Check the URL and any recent route changes.', 'Check the proxy forwards this path.', 'Check the build deployed this page.'],
      [
        _r(86, 'The response is HTTP 404', (x) => x.s == 404),
        _r(8, 'The site root answers', (x) => x.s == 404 && x.rootOk),
      ]),
  _d('method', 'The route does not accept GET', 'Request / auth', 'The route exists but only for other methods.',
      ['Use the right HTTP method.'], [_r(88, 'The response is HTTP 405', (x) => x.s == 405)]),
  _d('too_large', 'A size limit rejected the request', 'Proxy / load balancer', 'A proxy or server limit on body, header or URL size was exceeded.',
      ['Raise client_max_body_size or the equivalent.', 'Clear oversized cookies.'],
      [_r(86, 'The response is HTTP 413, 414 or 431', (x) => const [413, 414, 431].contains(x.s))]),
  _d('vhost', 'No virtual host matches this request', 'Proxy / load balancer', 'The server does not know this host or SNI name.',
      ['Add a server block or ingress rule for this host.', 'Check SNI and Host header handling.'],
      [_r(84, 'The response is HTTP 421', (x) => x.s == 421)]),
  _d('geo', 'The content is blocked in this region', 'Request / auth', 'Access is denied for legal or geographic reasons.',
      ['Test from an allowed region.'], [_r(86, 'The response is HTTP 451', (x) => x.s == 451)]),
  _d('disk_full', 'The server disk is full', 'Origin server', 'The server cannot write and fails requests.',
      ['Free disk space (logs, temp files, old releases).', 'Add storage and alert on disk use.'],
      [_r(88, 'The response is HTTP 507', (x) => x.s == 507)]),
  _d('maintenance', 'The site is in maintenance mode', 'Origin server', 'Someone took the site offline on purpose.',
      ['Finish the maintenance and disable the flag.'],
      [
        _r(42, 'The page mentions maintenance', (x) => x.s == 503 && (x.has('maintenance') || x.has('back soon'))),
        _r(14, 'A Retry-After header was sent', (x) => x.s == 503 && x.hdr('retry-after')),
      ]),
  _d('proto_ver', 'HTTP version not supported', 'Proxy / load balancer', 'Client and server cannot agree on an HTTP version.',
      ['Enable HTTP/1.1 on the server or proxy.'], [_r(84, 'The response is HTTP 505', (x) => x.s == 505)]),
  _d('empty_ok', 'The server returns 200 with an empty body', 'Origin server', 'A crashed handler or bad proxy rule can send success with nothing.',
      ['Check the handler returns content.', 'Check proxy rules and caches for an empty cached response.'],
      [_r(72, 'HTTP 200 with no content', (x) => x.s == 200 && x.p.body.trim().isEmpty && !x.p.truncated)]),
  _d('api_html', 'An API path returned a web page', 'Proxy / load balancer', 'A login page, error page or wrong route replaced the JSON.',
      ['Check the gateway routes /api to the API service.', 'Check auth is not redirecting API calls to a login page.'],
      [_r(62, 'The response is HTML on an /api path', (x) => x.ct.contains('html') && x.p.url.path.contains('/api'))]),
  _d('json_bad', 'The API returns invalid JSON', 'Origin server', 'The response claims to be JSON but cannot be parsed.',
      ['Check for stray output or debug prints before the JSON.', 'Check a proxy is not truncating the body.'],
      [
        _r(64, 'The body is not valid JSON', (x) {
          if (!x.ct.contains('json') || x.p.body.isEmpty || x.p.truncated || x.p.body.length >= 60000) return false;
          final t = x.p.body.trimLeft();
          return !(t.startsWith('{') || t.startsWith('[')) || t.startsWith('<');
        }),
      ]),
  _d('error_in_200', 'An error is returned with a success status', 'Origin server', 'The API says 200 but the body reports an error, which hides failures from monitors.',
      ['Return proper 4xx and 5xx codes for errors.'],
      [_r(52, 'The 200 body starts with an error object', (x) => x.s == 200 && RegExp(r'^\s*\{\s*"(error|errors|exception)"\s*:').hasMatch(x.p.body))]),
  _d('assets', 'Page files are missing or failing to load', 'Page assets', 'The HTML loads but scripts, styles or images fail, so the page looks broken.',
      ['Redeploy the missing files.', 'Check the CDN or bucket serving them.', 'Serve everything over HTTPS.'],
      [_rd(66, (x) => '${x.p.audit!.issues.length} of ${x.p.audit!.total} files have problems', (x) => x.p.audit != null && x.p.audit!.issues.isNotEmpty)]),
  _d('cdn_cache_err', 'The CDN could not get a valid reply from the origin', 'Proxy / load balancer', 'The edge reports an error fetching from the origin.',
      ['Check the origin is up and reachable from the CDN.', 'Purge any cached error response.'],
      [_r(72, 'The x-cache header reports an error', (x) => x.hv('x-cache').contains('error'))]),
  _d('aws_gw', 'API Gateway or Lambda failed the request', 'Origin server', 'AWS reported an error type on the response.',
      ['Check the Lambda logs and API Gateway integration.', 'Check timeouts and permissions.'],
      [_rd(74, (x) => 'x-amzn-errortype: ${x.p.headers['x-amzn-errortype']}', (x) => x.hdr('x-amzn-errortype'))]),
  _d('vercel_err', 'The Vercel deployment returned an error', 'Origin server', 'Vercel reported an error code for this request.',
      ['Check the deployment and function logs on Vercel.'],
      [_rd(78, (x) => 'x-vercel-error: ${x.p.headers['x-vercel-error']}', (x) => x.hdr('x-vercel-error'))]),
  _d('serverless_timeout', 'A serverless function timed out or cold-started', 'Origin server', 'Functions that sleep take long to wake, and fail if they exceed their limit.',
      ['Raise the function timeout or memory.', 'Keep it warm or move slow work to a queue.'],
      [
        _r(40, 'A 504 came from a serverless platform', (x) => x.s == 504 && (x.p.cdn == 'Vercel' || x.hdr('x-amzn-requestid') || x.hdr('x-amz-apigw-id'))),
        _r(14, 'It is slow before it fails', (x) => x.verySlow),
      ]),
  _d('very_slow', 'The server responds very slowly', 'Origin server', 'First byte is far slower than normal.',
      ['Profile the endpoint.', 'Check CPU, memory and database load.', 'Add caching.'],
      [
        _rd(60, (x) => 'First byte took ${_sec(x.ttfb)}', (x) => x.ttfb > 10000),
        _rd(34, (x) => 'First byte took ${_sec(x.ttfb)}', (x) => x.ttfb > 3000 && x.ttfb <= 10000),
      ]),
];

// Origin errors Cloudflare names explicitly.
final List<_Def> _cloudflare = [
  for (final e in <(int, String, String, String, String)>[
    (520, 'Cloudflare: the origin sent an empty or unknown reply', 'Origin server', 'The origin crashed or closed the connection without a proper reply.', 'Check the app logs for a crash and the origin\'s keep-alive limits.'),
    (521, 'Cloudflare: the origin refused the connection', 'Origin server', 'The web server is down or refusing Cloudflare.', 'Start the origin web server and allow Cloudflare IP ranges.'),
    (522, 'Cloudflare: connecting to the origin timed out', 'Origin server', 'The origin is unreachable, overloaded, or a firewall blocks Cloudflare.', 'Allow Cloudflare IPs in the firewall and check origin load.'),
    (523, 'Cloudflare: cannot route to the origin', 'DNS', 'The origin IP in Cloudflare DNS is wrong or unreachable.', 'Fix the origin A record in Cloudflare.'),
    (524, 'Cloudflare: the origin answered too slowly', 'Origin server', 'The connection opened but the reply took over 100 seconds.', 'Find the slow request; move long work to a background job.'),
    (525, 'Cloudflare: TLS handshake with the origin failed', 'TLS / certificate', 'The origin\'s TLS settings do not match Cloudflare\'s mode.', 'Install a valid certificate on the origin or change the SSL mode.'),
    (526, 'Cloudflare: the origin certificate is invalid', 'TLS / certificate', 'The origin certificate is expired or untrusted.', 'Renew or replace the origin certificate.'),
    (530, 'Cloudflare: the origin could not be resolved', 'DNS', 'Cloudflare could not find the origin by DNS.', 'Check the origin hostname and DNS records.'),
  ])
    _d('cf_${e.$1}', e.$2, e.$3, e.$4, [e.$5], [
      _r(90, 'HTTP ${e.$1} with a cf-ray header', (x) => x.cf && x.s == e.$1),
    ]),
];

final List<_Def> _all = [..._structural, ..._cloudflare];

/// Scores every possible cause against the evidence and returns the best ones.
List<RootCause> rankCauses(ProbeResult p, {int? backendScore}) {
  final x = Facts(p, backendScore);
  final out = <RootCause>[];

  for (final d in _all) {
    var score = 0;
    var positive = false;
    final support = <String>[];
    final against = <String>[];
    for (final r in d.rules) {
      bool hit;
      try {
        hit = r.test(x);
      } catch (_) {
        hit = false;
      }
      if (!hit) continue;
      score += r.w;
      if (r.w > 0) {
        positive = true;
        support.add(r.note(x));
      } else {
        against.add(r.note(x));
      }
    }
    if (!positive || score < 20) continue;
    out.add(RootCause(d.cause, score.clamp(0, 100).toInt(), support, against));
  }

  // Text the server itself returned is the strongest clue about what broke.
  if (x.body.isNotEmpty) {
    final seen = <String>{};
    final failing = (x.s ?? 0) >= 400 || p.truncated;
    for (final (pat, sev, title, detail, layer) in kSignatures) {
      final i = x.body.indexOf(pat);
      if (i < 0 || !seen.add(title)) continue;
      var score = sev == 2 ? 66 : 48;
      score += failing ? 14 : -14;
      if (pat.length >= 18) score += 8;
      if (sev == 2 && (x.s ?? 0) >= 500) score += 6;
      if (score < 20) continue;
      out.add(RootCause(
        Cause('sig:$pat', title, layer, detail, layerSteps[layer] ?? const <String>[]),
        score.clamp(0, 98).toInt(),
        ['The response body contains: "${snippet(p.body, i, pat.length)}"'],
        const [],
      ));
    }
  }

  // Independent signals pointing at the same layer reinforce each other.
  final bonus = <int>[];
  for (var i = 0; i < out.length; i++) {
    var others = 0;
    for (var j = 0; j < out.length; j++) {
      if (i != j && out[j].cause.layer == out[i].cause.layer && out[j].score >= 45) others++;
    }
    bonus.add(out[i].score >= 45 ? (others * 4 > 8 ? 8 : others * 4) : 0);
  }
  final boosted = <RootCause>[
    for (var i = 0; i < out.length; i++)
      RootCause(out[i].cause, (out[i].score + bonus[i]).clamp(0, 100).toInt(), out[i].support, out[i].against),
  ];

  final order = List<int>.generate(boosted.length, (i) => i)
    ..sort((a, b) {
      final c = boosted[b].score.compareTo(boosted[a].score);
      return c != 0 ? c : a.compareTo(b);
    });
  final seenTitles = <String>{};
  final ranked = <RootCause>[];
  for (final i in order) {
    if (seenTitles.add(boosted[i].cause.title)) ranked.add(boosted[i]);
    if (ranked.length >= 6) break;
  }
  return ranked;
}

/// Things the probe checked and found fine, so the reader can skip them.
List<String> ruledOut(ProbeResult p) {
  final o = <String>[];
  if (p.deviceOffline || p.dnsError != null) return o;
  if (p.addrs.isNotEmpty) {
    final n = p.addrs.length;
    o.add('DNS resolves ($n address${n == 1 ? '' : 'es'})');
  }
  if (p.ipMs.isNotEmpty && p.ipErr.isEmpty) o.add('Every server accepts connections');
  if (p.tcpMs != null && p.ipErr.isNotEmpty && p.ipMs.values.whereType<int>().isNotEmpty) {
    o.add('At least one server accepts connections');
  }
  if (p.tlsError == null && p.tlsMs != null) {
    o.add('Certificate is valid${p.tlsDays != null ? ' (${p.tlsDays} days left)' : ''}');
  }
  if (p.status != null) o.add('The server answers HTTP');
  if (p.httpError == null && p.status != null) o.add('No redirect loop');
  if (p.status != null && !p.truncated) o.add('The response arrives in full');
  if (p.repeats.length > 1 && p.repeats.every((c) => c != null && c < 500)) o.add('Repeated requests all succeed');
  if (p.companions['/'] != null && p.companions['/']! < 500) o.add('The site root answers');
  if ([p.companions['/health'], p.companions['/healthz']].any((c) => c == 200)) o.add('The health endpoint is OK');
  if (p.ipStatus.length > 1 && p.ipStatus.values.every((c) => c != null && c < 500)) o.add('Every server returns a good response when asked directly');
  if (p.audit != null && p.audit!.total > 0 && p.audit!.issues.isEmpty) o.add('All page files load');
  if (p.browserStatus == null && p.status != null && p.status! < 400) o.add('Not blocked as a bot');
  return o;
}

String causesText(List<RootCause> causes, List<String> ruled) {
  final b = StringBuffer('\nRoot cause ranking:\n');
  if (causes.isEmpty) b.writeln('- No single cause stands out.');
  for (final c in causes) {
    b.writeln('- ${c.score}% ${c.cause.title} [${c.cause.layer}]');
    for (final s in c.support) {
      b.writeln('    evidence: $s');
    }
    for (final s in c.against) {
      b.writeln('    against: $s');
    }
  }
  if (ruled.isNotEmpty) b.writeln('\nRuled out: ${ruled.join('; ')}');
  return b.toString();
}
