import 'probe.dart';

class Finding {
  Finding(this.severity, this.title, [this.detail = '']);
  final int severity; // 0 info, 1 warning, 2 problem
  final String title;
  final String detail;
}

const _cloudflare = {
  520: "Cloudflare got an empty or unknown reply from the origin. The app probably crashed or closed the connection.",
  521: "The origin refused Cloudflare's connection. The web server is probably down.",
  522: "Connecting to the origin timed out. The server is unreachable, overloaded, or a firewall is blocking Cloudflare.",
  523: "Cloudflare cannot route to the origin. Check the origin IP and DNS record.",
  524: "The origin accepted the connection but took too long to answer. Look for slow queries or a hung dependency.",
  525: "TLS handshake between Cloudflare and the origin failed. Check the origin's certificate and TLS settings.",
  526: "The origin's TLS certificate is invalid or expired.",
  530: "Cloudflare could not resolve or reach the origin. Often an origin DNS problem.",
};

const _generic = {
  500: "The app threw an error. Only its logs or Sentry can show which one.",
  502: "A gateway or proxy got an invalid reply from the app behind it. The app likely crashed or is not running.",
  503: "Service unavailable: overloaded, in maintenance, or no healthy backends.",
  504: "The gateway gave up waiting for the app. Look for slow queries or a hung dependency.",
};

// pattern (lowercase), severity, title, detail
const _signatures = [
  ('debug = true', 1, 'Django debug page exposed', 'DEBUG is on in production. The page may show the exception and stack trace.'),
  ('whoops, looks like something went wrong', 2, 'Laravel error page', 'The PHP app threw an unhandled exception. Check storage/logs/laravel.log.'),
  ('whitelabel error page', 2, 'Spring Boot error page', 'An unhandled exception reached the default handler. Check the application logs.'),
  ('traceback (most recent call last)', 2, 'Python stack trace in response', 'Read the last line of the traceback for the exception.'),
  ('fatal error:', 2, 'PHP fatal error in response', 'The page printed a PHP fatal error. Check the PHP error log.'),
  ('econnrefused', 2, 'Connection refused to a backend', 'A dependency (database, cache or upstream service) is not accepting connections.'),
  ('attention required! | cloudflare', 1, 'Blocked by a Cloudflare challenge', 'The probe was challenged. This is not the app failing, and real users may be fine.'),
  ('error 1020', 1, 'Blocked by a Cloudflare firewall rule', 'Access was denied by a WAF rule, not by an outage.'),
  ('application error', 1, 'Platform error page', 'Hosting platforms such as Heroku show this when the app process crashed or timed out.'),
  ('cannot get /', 0, 'Express route not found', 'The Node app is running but has no route for this path.'),
];

List<Finding> inspect(ProbeResult p) {
  final f = <Finding>[];
  final s = p.status;
  final h = p.headers;
  final body = p.body.toLowerCase();

  if (s != null) {
    final cf = _cloudflare[s];
    if (cf != null && p.cdn == 'Cloudflare') {
      f.add(Finding(2, 'Cloudflare error $s', cf));
    } else if (_generic.containsKey(s)) {
      f.add(Finding(2, '$s ${p.reason ?? ''}'.trim(), _generic[s]!));
    } else if (s == 429) {
      final ra = h['retry-after'];
      f.add(Finding(1, 'Rate limited (429)', ra != null ? 'Retry after $ra.' : 'Too many requests from this client.'));
    } else if (s == 401 || s == 403) {
      f.add(Finding(1, 'Access denied ($s)', 'Authentication or a firewall blocked the probe. This may not be an outage.'));
    } else if (s == 404) {
      f.add(Finding(1, 'Not found (404)', 'Check that the path is correct.'));
    }
    if (s == 502 || s == 503 || s == 504) {
      if (body.contains('nginx')) {
        f.add(Finding(1, 'Error page from nginx', 'nginx is up but cannot reach the app behind it. Check the app process and its port.'));
      } else if (body.contains('apache')) {
        f.add(Finding(1, 'Error page from Apache', 'Apache is up but its backend failed.'));
      }
    }
  }

  var matches = 0;
  for (final (pattern, sev, title, detail) in _signatures) {
    if (matches < 3 && body.contains(pattern)) {
      f.add(Finding(sev, title, detail));
      matches++;
    }
  }

  if (p.redirects.length >= 3) {
    f.add(Finding(1, 'Long redirect chain (${p.redirects.length} hops)', p.redirects.join('\n')));
  } else if (p.redirects.isNotEmpty) {
    f.add(Finding(0, 'Redirects', p.redirects.join('\n')));
  }

  if (p.repeats.length > 1) {
    final bad = p.repeats.where((x) => x == null || x >= 500).length;
    final n = p.repeats.length;
    if (bad == n) {
      f.add(Finding(2, 'Consistent failure', 'All $n requests failed. This is a hard outage, not a blip.'));
    } else if (bad > 0) {
      f.add(Finding(2, 'Intermittent failure', '$bad of $n requests failed. Suggests one unhealthy instance, a flaky dependency, or load balancer trouble.'));
    }
  }

  if ((p.ttfbMs ?? 0) > 3000) {
    f.add(Finding(1, 'Slow response', 'First byte took ${(p.ttfbMs! / 1000).toStringAsFixed(1)}s.'));
  }
  if (p.tlsDays != null && p.tlsDays! < 14) {
    f.add(Finding(p.tlsDays! < 3 ? 2 : 1, 'Certificate expires soon', '${p.tlsDays} days left.'));
  }
  if (h['x-ratelimit-remaining'] == '0') {
    f.add(Finding(1, 'Rate limit exhausted', 'x-ratelimit-remaining is 0.'));
  }
  if (h['cf-cache-status'] != null) {
    f.add(Finding(0, 'Cache status', 'Cloudflare: ${h['cf-cache-status']}'));
  }
  final stack = [if (p.server != null) 'server: ${p.server}', if (h['x-powered-by'] != null) 'x-powered-by: ${h['x-powered-by']}'];
  if (stack.isNotEmpty) f.add(Finding(0, 'Stack hints', stack.join(', ')));

  return f;
}
