import 'dart:convert';
import 'dart:io';
import 'probe.dart';
import 'signatures.dart';

class Finding {
  Finding(this.severity, this.title,
      [this.detail = '', this.layer, this.evidence, this.confidence = 2, this.fixes]);
  final int severity; // 0 info, 1 warning, 2 problem
  final String title;
  final String detail;
  final String? layer;
  final String? evidence; // what the probe actually saw
  final int confidence; // 0 possible, 1 likely, 2 confirmed
  final List<String>? fixes;
}

String confName(int c) => c == 2 ? 'Confirmed' : (c == 1 ? 'Likely' : 'Possible');

String snippet(String raw, int idx, int len) {
  if (idx < 0 || idx >= raw.length) return '';
  final a = idx - 60 < 0 ? 0 : idx - 60;
  final b = idx + len + 80 > raw.length ? raw.length : idx + len + 80;
  final s = raw.substring(a, b).replaceAll(RegExp(r'<[^>]*>'), ' ').replaceAll(RegExp(r'\s+'), ' ').trim();
  return s.length > 160 ? s.substring(0, 160) : s;
}

const _priority = [
  'Your connection',
  'DNS',
  'Network',
  'TLS / certificate',
  'Database / dependency',
  'Origin server',
  'Proxy / load balancer',
  'Firewall / bot protection',
  'Request / auth',
  'Page assets',
];

const layerSteps = <String, List<String>>{
  'Your connection': ['Check Wi-Fi or mobile data.', 'Try another network, then run the check again.'],
  'DNS': ['Confirm the domain has not expired at your registrar.', 'Check the A, AAAA or CNAME records at your DNS provider.', 'If you changed records recently, wait for DNS to propagate.'],
  'Network': ['Check the server or VM is running.', 'Check the firewall or security group allows the port.', 'Check the load balancer has healthy targets.'],
  'TLS / certificate': ['Renew or reinstall the certificate.', 'Serve the full certificate chain.', 'Make sure this domain name is on the certificate.'],
  'Database / dependency': ['Check the database is up and accepting connections.', 'Check connection pool size and slow queries.', 'Look at recent credential or schema changes.'],
  'Origin server': ['Read the app logs around the time of the failure.', 'Check the app process is running, and restart it if it crashed.', 'Check CPU, memory and disk on the host.', 'If it started after a deploy, roll that deploy back.'],
  'Proxy / load balancer': ['Check the backend health checks.', 'Check proxy timeouts and size limits.', 'Check the app listens on the port the proxy expects.'],
  'Firewall / bot protection': ['Allow-list your monitoring IP.', 'Review WAF and rate-limit rules.', 'Test again from a different network.'],
  'Request / auth': ['Check the URL path and method.', 'Check tokens or credentials.', 'Check API gateway routes.'],
  'Page assets': ['Fix or redeploy the missing files listed in Findings.', 'Check the CDN or storage bucket serving them.', 'Serve everything over HTTPS.'],
};

/// The earliest failing layer on the request path, preferring the most specific cause.
String? verdict(List<Finding> f) {
  for (final minConf in [1, 0]) {
    for (final sev in [2, 1]) {
      for (final l in _priority) {
        if (f.any((x) => x.severity == sev && x.layer == l && x.confidence >= minConf)) return l;
      }
    }
  }
  return null;
}

const _status = <int, (String, String, String)>{
  400: ('Bad request', 'The server rejected the request as malformed.', 'Request / auth'),
  401: ('Unauthorized', 'Credentials are required or invalid. Not an outage.', 'Request / auth'),
  403: ('Forbidden', 'Access refused by permissions, IP rules or a firewall.', 'Request / auth'),
  404: ('Not found', 'The path does not exist. Check the URL and routing rules.', 'Request / auth'),
  405: ('Method not allowed', 'The route exists but does not accept GET.', 'Request / auth'),
  408: ('Request timeout', 'The server gave up waiting for the request.', 'Request / auth'),
  410: ('Gone', 'The resource was removed on purpose.', 'Request / auth'),
  413: ('Payload too large', 'A size limit on the proxy or server was exceeded.', 'Proxy / load balancer'),
  414: ('URL too long', 'The URL exceeds the server limit.', 'Request / auth'),
  421: ('Misdirected request', 'Host or SNI does not match any virtual host.', 'Proxy / load balancer'),
  422: ('Unprocessable', 'The request was understood but failed validation.', 'Request / auth'),
  429: ('Rate limited', 'Too many requests from this client.', 'Request / auth'),
  451: ('Blocked for legal reasons', 'The content is blocked in this region.', 'Request / auth'),
  460: ('Load balancer: client closed connection', 'The client gave up before the AWS load balancer replied.', 'Proxy / load balancer'),
  463: ('Load balancer: too many forwarded IPs', 'The X-Forwarded-For header is too long.', 'Proxy / load balancer'),
  500: ('Internal server error', 'The app threw an unhandled error. Only its logs or Sentry show which one.', 'Origin server'),
  501: ('Not implemented', 'The server does not support this request.', 'Origin server'),
  502: ('Bad gateway', 'A proxy got an invalid reply from the app behind it. The app likely crashed or is not running.', 'Origin server'),
  503: ('Service unavailable', 'Overloaded, in maintenance, or no healthy backends.', 'Origin server'),
  504: ('Gateway timeout', 'The proxy gave up waiting for the app. Look for slow queries or a hung dependency.', 'Origin server'),
  505: ('HTTP version not supported', 'Protocol mismatch between client and server.', 'Proxy / load balancer'),
  507: ('Insufficient storage', 'The server disk is full.', 'Origin server'),
  508: ('Loop detected or resource limit', 'The server hit a loop or a hosting resource limit.', 'Origin server'),
  511: ('Network login required', 'A captive portal (Wi-Fi login page) is intercepting traffic.', 'Network'),
  561: ('Load balancer: auth failed', 'The ALB identity provider rejected the user.', 'Proxy / load balancer'),
};

const _cloudflare = <int, (String, String)>{
  520: ('Empty or unknown reply from the origin. The app probably crashed or closed the connection.', 'Origin server'),
  521: ("The origin refused Cloudflare's connection. The web server is probably down.", 'Origin server'),
  522: ('Connecting to the origin timed out. The server is unreachable, overloaded, or a firewall blocks Cloudflare.', 'Origin server'),
  523: ('Cloudflare cannot route to the origin. Check the origin IP and DNS record.', 'DNS'),
  524: ('The origin accepted the connection but took too long to answer. Look for slow queries.', 'Origin server'),
  525: ("TLS handshake between Cloudflare and the origin failed. Check the origin's TLS settings.", 'TLS / certificate'),
  526: ("The origin's TLS certificate is invalid or expired.", 'TLS / certificate'),
  530: ('Cloudflare could not resolve or reach the origin. Often an origin DNS problem.', 'DNS'),
};


String timingLine(ProbeResult p) {
  final parts = <String>[];
  if (p.dnsMs != null) parts.add('DNS ${p.dnsMs}ms');
  if (p.tcpMs != null) parts.add('connect ${p.tcpMs}ms');
  if (p.tlsMs != null) parts.add('TLS ~${p.tlsMs}ms');
  if (p.ttfbMs != null) parts.add('first byte ${p.ttfbMs}ms');
  if (p.totalMs != null && p.ttfbMs != null) parts.add('download ${p.totalMs! - p.ttfbMs!}ms');
  return parts.join(' · ');
}

bool _private(InternetAddress a) {
  if (a.type != InternetAddressType.IPv4) return false;
  final b = a.rawAddress;
  return b[0] == 10 || (b[0] == 172 && b[1] >= 16 && b[1] <= 31) || (b[0] == 192 && b[1] == 168);
}

List<Finding> inspect(ProbeResult p) {
  final f = <Finding>[];
  final h = p.headers;
  final s = p.status;
  final body = p.body.toLowerCase();

  if (p.deviceOffline) {
    return [
      Finding(2, 'Your device looks offline', 'The phone could not reach the internet at all, so this says nothing about the site.', 'Your connection'),
    ];
  }

  // ---- DNS ----
  if (p.dnsError != null) {
    final e = p.dnsError!;
    f.add(Finding(
        2,
        'DNS: $e',
        e == 'Invalid URL'
            ? 'Enter a full address such as https://example.com/path.'
            : 'The domain does not resolve. It may be misspelled, expired, or its DNS records were removed. Check the registrar and nameservers.',
        'DNS'));
    return f;
  }
  for (final a in p.addrs) {
    if (a.isLoopback) {
      f.add(Finding(2, 'Resolves to localhost', 'DNS points to ${a.address}, which no outside client can reach.', 'DNS'));
    } else if (_private(a)) {
      f.add(Finding(1, 'Resolves to a private IP', '${a.address} is not reachable from the internet.', 'DNS'));
    }
  }
  if ((p.dnsMs ?? 0) > 1000) {
    f.add(Finding(1, 'Slow DNS', 'Lookup took ${p.dnsMs}ms. Check the DNS provider.', 'DNS'));
  }

  // ---- Network: every address ----
  if (p.ipErr.isNotEmpty) {
    final real = p.ipErr.entries
        .where((e) => !(e.key.contains(':') && (e.value.contains('unreachable') || e.value.contains('No route'))))
        .toList();
    final v6 = p.ipErr.length - real.length;
    if (real.isNotEmpty) {
      final all = p.tcpMs == null;
      f.add(Finding(
          2,
          all ? 'No server is reachable' : 'Some servers are down',
          '${real.length} of ${p.ipMs.length} addresses failed:\n${real.map((e) => '${e.key}: ${e.value}').join('\n')}${all ? '' : '\nRequests landing on these fail at random.'}',
          'Network'));
    }
    if (v6 > 0) {
      f.add(Finding(0, 'IPv6 not reachable from this network', 'Normal on many mobile and home networks.'));
    }
  }
  if (p.tcpMs == null) return f;
  if (p.tcpMs! > 1000) {
    f.add(Finding(1, 'Slow connection', 'TCP connect took ${p.tcpMs}ms: distance, packet loss or an overloaded host.', 'Network'));
  }

  // ---- TLS ----
  if (p.tlsError != null) {
    final e = p.tlsError!;
    var help = 'The secure connection could not be established.';
    if (e.contains('expired')) help = 'Renew the certificate. Check that auto-renewal (e.g. certbot) is running.';
    if (e.contains('hostname')) help = 'The certificate was issued for a different domain. Add this name to it.';
    if (e.contains('Self-signed')) help = 'Browsers and apps will reject it. Use a certificate from a trusted CA.';
    if (e.contains('chain')) help = 'The server is missing its intermediate certificate. Serve the full chain.';
    if (e.contains('protocol')) help = 'Client and server share no TLS version or cipher.';
    f.add(Finding(2, 'TLS: $e', help, 'TLS / certificate'));
    return f;
  }
  if (p.tlsDays != null) {
    if (p.tlsDays! < 14) {
      f.add(Finding(p.tlsDays! < 3 ? 2 : 1, 'Certificate expires soon', '${p.tlsDays} days left.', 'TLS / certificate'));
    }
    if (p.tlsStart != null && p.tlsStart!.isAfter(DateTime.now())) {
      f.add(Finding(2, 'Certificate not valid yet', 'Its start date is in the future. Check the server clock.', 'TLS / certificate'));
    }
  }
  if ((p.tlsMs ?? 0) > 1500) f.add(Finding(1, 'Slow TLS handshake', '${p.tlsMs}ms.', 'TLS / certificate'));

  final tl = timingLine(p);
  if (tl.isNotEmpty) f.add(Finding(0, 'Timing breakdown', tl));

  // ---- HTTP ----
  if (p.httpError != null) {
    final e = p.httpError!;
    var help = 'The request failed after connecting.';
    var layer = 'Origin server';
    if (e.contains('Timed out')) help = 'The server accepted the connection but never answered. The app is hung, overloaded, or waiting on a dependency.';
    if (e.contains('redirects')) {
      help = 'A redirect loop. HTTP/HTTPS or www rules often fight each other.';
      layer = 'Proxy / load balancer';
    }
    if (e.contains('reset')) help = 'The server dropped the connection: crash, restart or a proxy limit.';
    if (e.contains('refused')) help = 'Nothing is listening on this port. The service is down.';
    f.add(Finding(2, e, help, layer));
  }
  if (p.truncated) {
    f.add(Finding(2, 'Response cut off', '${p.bodyError ?? 'The connection ended early'}. The server or proxy dropped the connection mid-response.', 'Proxy / load balancer'));
  }

  if (s != null) {
    final cf = _cloudflare[s];
    final st = _status[s];
    if (cf != null && p.cdn == 'Cloudflare') {
      f.add(Finding(2, 'Cloudflare error $s', cf.$1, cf.$2, 'HTTP $s with a Cloudflare cf-ray header', 2));
    } else if (st != null) {
      f.add(Finding(s >= 500 ? 2 : 1, '$s ${st.$1}', st.$2, st.$3,
          'HTTP $s${p.reason != null ? ' ${p.reason}' : ''}${p.server != null ? ' from ${p.server}' : ''}',
          s >= 500 ? 1 : 2));
    } else if (s >= 500) {
      f.add(Finding(2, 'Server error $s', 'The server reported an error.', 'Origin server'));
    }
    if (s == 429 && h['retry-after'] != null) {
      f.add(Finding(0, 'Retry-After', 'Wait ${h['retry-after']}.'));
    }
  }

  // ---- Headers ----
  final vErr = h['x-vercel-error'];
  if (vErr != null) f.add(Finding(2, 'Vercel error: $vErr', 'Check the deployment and function logs.', 'Origin server'));
  final aErr = h['x-amzn-errortype'];
  if (aErr != null) f.add(Finding(2, 'AWS error: $aErr', 'API Gateway or Lambda rejected or failed the request.', 'Origin server'));
  if ((h['x-cache'] ?? '').toLowerCase().contains('error')) {
    f.add(Finding(2, 'CDN could not get a valid origin response', 'x-cache reports an error.', 'Origin server'));
  }
  if (h['x-ratelimit-remaining'] == '0') {
    f.add(Finding(1, 'Rate limit exhausted', 'x-ratelimit-remaining is 0.', 'Request / auth'));
  }

  // ---- Body signatures ----
  var hits = 0;
  for (final (pat, sev, title, detail, layer) in kSignatures) {
    if (hits < 4 && body.contains(pat)) {
      f.add(Finding(sev, title, detail, layer, 'Response body contains: "${snippet(p.body, body.indexOf(pat), pat.length)}"', 2));
      hits++;
    }
  }

  // ---- Content sanity ----
  if (s == 200) {
    if (p.body.trim().isEmpty && !p.truncated) {
      f.add(Finding(1, 'Empty response', '200 OK with no body. A crashed handler or bad proxy rule can do this.', 'Origin server'));
    }
    final ct = p.contentType ?? '';
    if (ct.contains('json') && p.body.isNotEmpty && !p.truncated && p.body.length < 60000) {
      try {
        jsonDecode(p.body);
        if (RegExp(r'^\s*\{\s*"(error|errors|exception)"\s*:').hasMatch(p.body)) {
          f.add(Finding(1, '200 OK but the body reports an error', 'The API returns errors with a success status.', 'Origin server'));
        }
      } catch (_) {
        f.add(Finding(1, 'Invalid JSON', 'The response claims to be JSON but cannot be parsed.', 'Origin server'));
      }
    }
    if (ct.contains('html') && p.url.path.contains('/api')) {
      f.add(Finding(1, 'API path returned a web page', 'An error page, login page or proxy page replaced the JSON.', 'Proxy / load balancer'));
    }
  }

  // ---- Redirects ----
  if (p.redirects.length >= 3) {
    f.add(Finding(1, 'Long redirect chain (${p.redirects.length} hops)', p.redirects.join('\n'), 'Proxy / load balancer'));
  } else if (p.redirects.isNotEmpty) {
    f.add(Finding(0, 'Redirects', p.redirects.join('\n')));
  }
  if (p.url.scheme == 'https' && p.redirects.any((r) => r.contains('-> http://'))) {
    f.add(Finding(1, 'Redirects to insecure HTTP', 'A downgrade from HTTPS. Check redirect rules.', 'Proxy / load balancer'));
  }
  if (p.redirects.isNotEmpty && RegExp(r'login|signin|sign-in|auth').hasMatch(p.redirects.last)) {
    f.add(Finding(0, 'Redirected to a login page', 'The page needs authentication.', 'Request / auth'));
  }

  // ---- Other endpoints on the same host ----
  final root = p.companions['/'];
  if (s != null && s >= 500 && p.companions.containsKey('/')) {
    if (root != null && root < 500) {
      f.add(Finding(2, 'Only this endpoint fails', 'The site root answers ($root), so the server is up. The fault is in this route: its code or a query it runs.', 'Origin server'));
    } else {
      f.add(Finding(2, 'The whole site is failing', 'The root URL fails too, so this is a host-wide or upstream outage.', 'Origin server'));
    }
  }
  for (final path in ['/health', '/healthz']) {
    if (!p.companions.containsKey(path)) continue;
    final c = p.companions[path];
    if (c == 200) {
      f.add(Finding(0, 'Health check $path is OK', 'The app answers its health endpoint.'));
    } else if (c != null && c >= 500) {
      f.add(Finding(2, 'Health check $path returns $c', 'The app reports itself unhealthy.', 'Origin server'));
    }
  }

  // ---- Inferred: slow failure on one route while the rest of the site answers ----
  final timedOut = (p.httpError ?? '').contains('Timed out');
  final failing = (s != null && s >= 500) || timedOut;
  if (failing && ((p.ttfbMs ?? 0) >= 5000 || timedOut) && root != null && root < 500) {
    final t = p.ttfbMs != null ? 'First byte after ${(p.ttfbMs! / 1000).toStringAsFixed(1)}s' : 'No reply before the timeout';
    f.add(Finding(
        2,
        'Possible dependency timeout (database or external API)',
        'This route fails slowly while the rest of the site answers. That pattern usually means the route waits on a database query or another service and gives up. The outside view cannot see the query, so this is an inference.',
        'Database / dependency',
        '$t${s != null ? ', status $s' : ''}; the site root answers $root.',
        0,
        [
          'Find the slowest query this route runs (slow query log, APM, EXPLAIN).',
          'Check database connection pool usage and max connections.',
          'Look for locks or long transactions at the time of failure.',
          'Check any external API this route calls for latency or outages.',
          'Add a query timeout, and an index if a table scan is the cause.',
        ]));
  }

  // ---- Direct-to-IP, browser and hostname cross-checks ----
  if (p.ipStatus.length > 1) {
    final bad = p.ipStatus.entries.where((e) => e.value == null || e.value! >= 500).toList();
    final good = p.ipStatus.entries.where((e) => e.value != null && e.value! < 500).toList();
    if (bad.isNotEmpty && good.isNotEmpty) {
      f.add(Finding(
          2,
          'One server behind the name is unhealthy',
          'Asked directly, ${bad.length} of ${p.ipStatus.length} addresses fail while the others answer. Users hit the bad one at random.',
          'Origin server',
          p.ipStatus.entries.map((e) => '${e.key} -> ${e.value ?? 'no reply'}').join('\n'),
          2,
          ['Remove the failing instance from the load balancer or DNS.', 'Read that instance\'s logs and restart or redeploy it.', 'Compare its config and version with a healthy instance.']));
    }
  }
  if (s != null && s >= 400 && p.browserStatus != null && p.browserStatus! < 400) {
    f.add(Finding(
        1,
        'Blocked unless the request looks like a browser',
        'The URL returns $s to this probe but ${p.browserStatus} to a browser user agent. A firewall or bot rule is rejecting automated clients; real users are probably fine.',
        'Firewall / bot protection',
        'probe user agent -> $s; browser user agent -> ${p.browserStatus}',
        2));
  }
  if (p.altHost != null && p.altStatus != null && s != null) {
    final altOk = p.altStatus! < 400;
    if (s >= 500 && altOk) {
      f.add(Finding(
          1,
          'The other hostname works',
          '${p.altHost} answers ${p.altStatus} while ${p.url.host} fails. The fault is tied to this hostname: its DNS record, virtual host or proxy rule.',
          'Proxy / load balancer',
          '${p.url.host} -> $s; ${p.altHost} -> ${p.altStatus}',
          1));
    }
  }

  // ---- Repeats ----
  if (p.repeats.length > 1) {
    final bad = p.repeats.where((x) => x == null || x >= 500).length;
    final n = p.repeats.length;
    if (bad == n) {
      f.add(Finding(2, 'Consistent failure', 'All $n requests failed. This is a hard outage, not a blip.', 'Origin server'));
    } else if (bad > 0) {
      f.add(Finding(2, 'Intermittent failure', '$bad of $n requests failed. Suggests one unhealthy instance, a flaky dependency, or load balancer trouble.', 'Origin server'));
    }
  }

  if ((p.ttfbMs ?? 0) > 10000) {
    f.add(Finding(2, 'Very slow response', 'First byte took ${(p.ttfbMs! / 1000).toStringAsFixed(1)}s.', 'Origin server'));
  } else if ((p.ttfbMs ?? 0) > 3000) {
    f.add(Finding(1, 'Slow response', 'First byte took ${(p.ttfbMs! / 1000).toStringAsFixed(1)}s.', 'Origin server'));
  }

  final a = p.audit;
  if (a != null && a.total > 0) {
    if (a.issues.isEmpty) {
      f.add(Finding(0, 'Page assets OK', 'All ${a.total} scripts, styles and images in the HTML loaded.'));
    } else {
      final sev = a.issues.any((x) => x.severity == 2) ? 2 : 1;
      f.add(Finding(
          sev,
          '${a.issues.length} of ${a.total} page assets have problems',
          a.issues.take(6).map((x) {
            final u = Uri.tryParse(x.url);
            final short = u == null ? x.url : '${u.host}${u.path}';
            return '${x.problem}: $short';
          }).join('\n'),
          'Page assets'));
    }
  }

  final stack = [
    if (p.server != null) 'server: ${p.server}',
    if (h['x-powered-by'] != null) 'x-powered-by: ${h['x-powered-by']}',
    if (p.cdn != null) 'CDN: ${p.cdn}',
  ];
  if (stack.isNotEmpty) f.add(Finding(0, 'Stack hints', stack.join(', ')));
  return f;
}

String buildReport(ProbeResult p, List<Finding> f, String? layer) {
  final b = StringBuffer()
    ..writeln('PingR report')
    ..writeln('URL: ${p.url}')
    ..writeln('Time: ${p.at.toIso8601String()}')
    ..writeln('Result: ${p.headline}')
    ..writeln('Failing layer: ${layer ?? 'none detected'}');
  final tl = timingLine(p);
  if (tl.isNotEmpty) b.writeln('Timing: $tl');
  if (p.ipMs.isNotEmpty) {
    b.writeln('Addresses: ${p.ipMs.entries.map((e) => '${e.key}=${e.value == null ? p.ipErr[e.key] : '${e.value}ms'}').join(', ')}');
  }
  if (p.companions.isNotEmpty) {
    b.writeln('Other paths: ${p.companions.entries.map((e) => '${e.key}=${e.value ?? 'fail'}').join(', ')}');
  }
  b.writeln('\nFindings:');
  for (final x in f) {
    b.writeln('- [${['info', 'warning', 'problem'][x.severity]}, ${confName(x.confidence).toLowerCase()}] ${x.title}${x.detail.isEmpty ? '' : ': ${x.detail.replaceAll('\n', ' ')}'}');
    if (x.evidence != null && x.evidence!.isNotEmpty) b.writeln('    saw: ${x.evidence}');
  }
  return b.toString();
}
