import 'dart:convert';
import 'dart:io';
import 'probe.dart';

class Finding {
  Finding(this.severity, this.title, [this.detail = '', this.layer]);
  final int severity; // 0 info, 1 warning, 2 problem
  final String title;
  final String detail;
  final String? layer;
}

const _priority = [
  'DNS',
  'Network',
  'TLS / certificate',
  'Database / dependency',
  'Origin server',
  'Proxy / load balancer',
  'Firewall / bot protection',
  'Request / auth',
];

/// The earliest failing layer on the request path, preferring the most specific cause.
String? verdict(List<Finding> f) {
  for (final sev in [2, 1]) {
    for (final l in _priority) {
      if (f.any((x) => x.severity == sev && x.layer == l)) return l;
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

// lowercase pattern, severity, title, detail, layer
const _sigs = <(String, int, String, String, String)>[
  // Databases and dependencies
  ('error establishing a database connection', 2, 'WordPress cannot reach its database', 'MySQL is down, overloaded or the credentials changed.', 'Database / dependency'),
  ('sqlstate', 2, 'SQL error in the response', 'A database query failed. Check the query and database health.', 'Database / dependency'),
  ('could not connect to server', 2, 'Database connection failed', 'The app could not open a connection to its database.', 'Database / dependency'),
  ('too many connections', 2, 'Database connection limit reached', 'Pool or server max connections exhausted. Close leaks or raise limits.', 'Database / dependency'),
  ('pooltimeout', 2, 'Connection pool exhausted', 'All pooled connections are busy. Look for slow queries or leaks.', 'Database / dependency'),
  ('mysql server has gone away', 2, 'MySQL connection dropped', 'The server closed an idle or oversized connection.', 'Database / dependency'),
  ('lock wait timeout exceeded', 2, 'Database lock timeout', 'A long transaction is blocking others.', 'Database / dependency'),
  ('deadlock found', 2, 'Database deadlock', 'Two transactions blocked each other.', 'Database / dependency'),
  ('mongoerror', 2, 'MongoDB error', 'The app failed talking to MongoDB.', 'Database / dependency'),
  ('redis connection', 2, 'Redis connection problem', 'Redis is unreachable or its pool is exhausted.', 'Database / dependency'),
  ('redis.exceptions', 2, 'Redis error', 'The Python Redis client raised an error.', 'Database / dependency'),
  ("can't reach database server", 2, 'Prisma cannot reach the database', 'Check the database URL and that the server is up.', 'Database / dependency'),
  ('econnrefused', 2, 'A backend refused a connection', 'A dependency (database, cache or API) is not accepting connections.', 'Database / dependency'),
  // Application crashes
  ('traceback (most recent call last)', 2, 'Python stack trace in response', 'Read the last line of the traceback for the exception.', 'Origin server'),
  ('debug = true', 1, 'Django debug page exposed', 'DEBUG is on in production. The page may show the exception.', 'Origin server'),
  ('whoops, looks like something went wrong', 2, 'Laravel error page', 'Unhandled PHP exception. Check storage/logs/laravel.log.', 'Origin server'),
  ('whitelabel error page', 2, 'Spring Boot error page', 'An unhandled exception reached the default handler.', 'Origin server'),
  ('fatal error:', 2, 'PHP fatal error', 'Check the PHP error log.', 'Origin server'),
  ('parse error:', 2, 'PHP parse error', 'A syntax error in deployed code.', 'Origin server'),
  ('allowed memory size', 2, 'PHP out of memory', 'Raise memory_limit or fix the leak.', 'Origin server'),
  ('maximum execution time', 2, 'PHP script timed out', 'A request ran longer than max_execution_time.', 'Origin server'),
  ('there has been a critical error on this website', 2, 'WordPress critical error', 'A plugin or theme crashed. Enable WP_DEBUG to see which.', 'Origin server'),
  ('application error: a server-side exception has occurred', 2, 'Next.js server exception', 'Check server logs using the digest shown on the page.', 'Origin server'),
  ("we're sorry, but something went wrong", 2, 'Rails error page', 'Check log/production.log.', 'Origin server'),
  ("server error in '/' application", 2, 'ASP.NET unhandled error', 'Check the event log or enable custom errors detail.', 'Origin server'),
  ('http error 500.', 2, 'IIS 500 error', 'The IIS site returned an error. See the sub-status code.', 'Origin server'),
  ('http status 500', 2, 'Tomcat 500 error', 'Check catalina.out for the stack trace.', 'Origin server'),
  ('nullpointerexception', 2, 'Java NullPointerException', 'Unhandled null in server code.', 'Origin server'),
  ('java.lang.outofmemoryerror', 2, 'Java out of memory', 'Heap exhausted. Raise -Xmx or fix the leak.', 'Origin server'),
  ('cannot find module', 2, 'Node module missing', 'A dependency was not installed in the deployment.', 'Origin server'),
  ('typeerror:', 2, 'JavaScript TypeError on server', 'Unhandled error in Node code.', 'Origin server'),
  ('referenceerror:', 2, 'JavaScript ReferenceError on server', 'Unhandled error in Node code.', 'Origin server'),
  ('an error occurred in the application and your page could not be served', 2, 'Heroku application error', 'The dyno crashed or timed out. Run heroku logs --tail.', 'Origin server'),
  ('application failed to respond', 2, 'Railway app not responding', 'The service crashed or listens on the wrong port.', 'Origin server'),
  ('http response was malformed or connection to the instance had an error', 2, 'Cloud Run container failed', 'The container crashed or ignored the PORT variable.', 'Origin server'),
  ('function_invocation_failed', 2, 'Vercel function crashed', 'Check function logs in the Vercel dashboard.', 'Origin server'),
  ('function_invocation_timeout', 2, 'Vercel function timed out', 'The function exceeded its time limit.', 'Origin server'),
  ('deployment_not_found', 2, 'Vercel deployment missing', 'The deployment was removed or the domain points to nothing.', 'Origin server'),
  ('currently stopped', 2, 'Azure web app is stopped', 'Start the app service in the Azure portal.', 'Origin server'),
  ("there isn't a github pages site here", 2, 'GitHub Pages site missing', 'Pages is not enabled or the build failed.', 'Origin server'),
  ('account has been suspended', 2, 'Hosting account suspended', 'Contact the host: unpaid bill or abuse suspension.', 'Origin server'),
  ('resource limit is reached', 2, 'Hosting resource limit hit', 'Shared hosting CPU or memory quota exceeded.', 'Origin server'),
  ('bandwidth limit exceeded', 2, 'Bandwidth quota exceeded', 'The hosting plan transfer quota is used up.', 'Origin server'),
  ('under maintenance', 1, 'Maintenance page', 'The site is deliberately offline.', 'Origin server'),
  ('maintenance mode', 1, 'Maintenance mode', 'The site is deliberately offline.', 'Origin server'),
  ('welcome to nginx!', 1, 'Default nginx page', 'The app is not deployed or the virtual host is misrouted.', 'Origin server'),
  ('apache2 ubuntu default page', 1, 'Default Apache page', 'The app is not deployed or the virtual host is misrouted.', 'Origin server'),
  ('this domain is for sale', 1, 'Parked domain', 'The domain is parked, expired or not pointed at your server.', 'DNS'),
  ('domain parking', 1, 'Parked domain', 'The domain is parked, expired or not pointed at your server.', 'DNS'),
  ('cannot get /', 1, 'Express route not found', 'The Node app is up but has no route for this path.', 'Origin server'),
  // Proxies and load balancers
  ('upstream connect error or disconnect/reset before headers', 2, 'Envoy/Istio cannot reach the service', 'The pod is down, restarting or refusing connections.', 'Proxy / load balancer'),
  ('no healthy upstream', 2, 'No healthy backends', 'All backends failed health checks.', 'Proxy / load balancer'),
  ('upstream request timeout', 2, 'Proxy timed out waiting for the app', 'The app is slow or hung.', 'Proxy / load balancer'),
  ('while connecting to upstream', 2, 'nginx cannot connect to upstream', 'The app process is down or listens elsewhere.', 'Proxy / load balancer'),
  ('upstream timed out', 2, 'nginx upstream timeout', 'The app took longer than proxy_read_timeout.', 'Proxy / load balancer'),
  ('upstream prematurely closed connection', 2, 'App closed the connection early', 'The app crashed mid-request.', 'Proxy / load balancer'),
  ('default backend - 404', 2, 'Kubernetes ingress has no matching route', 'Check the Ingress host, path and service.', 'Proxy / load balancer'),
  ('no server is available to handle this request', 2, 'HAProxy has no live backend', 'All servers in the pool are down.', 'Proxy / load balancer'),
  ('invalid response from an upstream server', 2, 'Apache proxy got an invalid reply', 'The backend returned something malformed or crashed.', 'Proxy / load balancer'),
  ('guru meditation', 2, 'Varnish backend failure', 'Varnish could not get a response from the backend.', 'Proxy / load balancer'),
  // Firewalls and bot protection
  ('attention required! | cloudflare', 1, 'Cloudflare blocked the probe', 'This is a challenge, not an outage. Real users may be fine.', 'Firewall / bot protection'),
  ('just a moment...', 1, 'Cloudflare browser challenge', 'The probe cannot pass this check.', 'Firewall / bot protection'),
  ('error 1020', 1, 'Cloudflare firewall rule blocked access', 'A WAF rule matched this request.', 'Firewall / bot protection'),
  ('error 1015', 1, 'Cloudflare rate limit hit', 'Too many requests from this IP.', 'Firewall / bot protection'),
  ('error 1010', 1, 'Cloudflare blocked the browser signature', 'The client was flagged as automated.', 'Firewall / bot protection'),
  ('error 1033', 2, 'Cloudflare Tunnel is down', 'The cloudflared connector is not running.', 'Origin server'),
  ('error 1016', 2, 'Cloudflare cannot resolve the origin', 'The origin DNS record is wrong or missing.', 'DNS'),
  ('error 1101', 2, 'Cloudflare Worker threw an exception', 'Check the Worker logs.', 'Origin server'),
  ('error 1102', 2, 'Cloudflare Worker exceeded resource limits', 'CPU or memory limit hit.', 'Origin server'),
  ('errors.edgesuite.net', 1, 'Akamai blocked the request', 'Access denied by the CDN edge.', 'Firewall / bot protection'),
  ('incapsula incident', 1, 'Imperva blocked the request', 'Access denied by the WAF.', 'Firewall / bot protection'),
  ('sucuri website firewall', 1, 'Sucuri blocked the request', 'Access denied by the WAF.', 'Firewall / bot protection'),
  ('captcha', 1, 'CAPTCHA challenge', 'Bot protection is challenging the probe.', 'Firewall / bot protection'),
];

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
      f.add(Finding(2, 'Cloudflare error $s', cf.$1, cf.$2));
    } else if (st != null) {
      f.add(Finding(s >= 500 ? 2 : 1, '$s ${st.$1}', st.$2, st.$3));
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
  for (final (pat, sev, title, detail, layer) in _sigs) {
    if (hits < 4 && body.contains(pat)) {
      f.add(Finding(sev, title, detail, layer));
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
    ..writeln('Triage report')
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
    b.writeln('- [${['info', 'warning', 'problem'][x.severity]}] ${x.title}${x.detail.isEmpty ? '' : ': ${x.detail.replaceAll('\n', ' ')}'}');
  }
  return b.toString();
}
