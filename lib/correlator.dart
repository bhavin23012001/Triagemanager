import 'dart:convert';
import 'package:http/http.dart' as http;
import 'probe.dart';
import 'settings.dart';

class Evidence {
  Evidence(this.source, this.title, {this.detail = '', this.at, this.url});
  final String source;
  final String title;
  final String detail;
  final DateTime? at;
  final String? url;
}

class Diagnosis {
  String summary = '';
  int score = 0;
  Evidence? error;
  Evidence? commit;
  final List<Evidence> timeline = [];
  final List<String> notes = [];
}

class Correlator {
  Correlator(this.s);
  final Settings s;

  Future<Diagnosis> diagnose(ProbeResult p) async {
    final d = Diagnosis();
    if (!p.failed) {
      d.summary = 'Healthy. ${p.headline} in ${p.ttfbMs}ms.';
      return d;
    }
    d.timeline.add(Evidence('Probe', p.headline, at: p.at));

    // Network-layer faults are fully diagnosable from outside.
    if (p.dnsError != null || p.tlsError != null) {
      d.score = 95;
      d.summary = '${p.headline}. This is a network-layer fault, visible without backend access.';
      return d;
    }

    d.score = 30;
    d.summary = '${p.headline}${p.cdn != null ? ' via ${p.cdn}' : ''}. The upstream origin failed.';

    if (s.hasSentry) {
      try {
        d.error = await _sentry(p);
        if (d.error != null) {
          d.score += 35;
          d.timeline.add(d.error!);
        } else {
          d.notes.add('No Sentry issue seen within 10 minutes of the failure.');
        }
      } catch (e) {
        d.notes.add('Sentry lookup failed: $e');
      }
    } else {
      d.notes.add('Connect Sentry to see the backend error behind this status.');
    }

    if (s.hasGithub) {
      try {
        d.commit = await _github(p);
        if (d.commit != null) {
          final mins = p.at.difference(d.commit!.at!).inMinutes;
          d.score += mins <= 120 ? 20 : 8;
          d.timeline.add(d.commit!);
        } else {
          d.notes.add('No commits in the 6 hours before the failure.');
        }
      } catch (e) {
        d.notes.add('GitHub lookup failed: $e');
      }
    }

    if (d.error != null) {
      d.summary = '${d.error!.title} (${d.error!.detail}) is the likely cause of the ${p.headline}.';
      if (d.commit != null) {
        d.summary += ' Latest deploy candidate: ${d.commit!.title}.';
      }
    }
    d.timeline.sort((a, b) => (a.at ?? p.at).compareTo(b.at ?? p.at));
    d.score = d.score.clamp(0, 100);
    return d;
  }

  Future<Evidence?> _sentry(ProbeResult p) async {
    final uri = Uri.https('sentry.io', '/api/0/projects/${s.sentryOrg}/${s.sentryProject}/issues/',
        {'statsPeriod': '24h', 'query': 'is:unresolved'});
    final r = await http
        .get(uri, headers: {'Authorization': 'Bearer ${s.sentryToken}'})
        .timeout(const Duration(seconds: 15));
    if (r.statusCode != 200) throw 'HTTP ${r.statusCode}';
    final issues = (jsonDecode(r.body) as List).cast<Map<String, dynamic>>();
    Evidence? best;
    var bestCount = -1;
    for (final i in issues) {
      final seen = DateTime.tryParse(i['lastSeen'] ?? '');
      if (seen == null || seen.difference(p.at).inMinutes.abs() > 10) continue;
      final count = int.tryParse('${i['count']}') ?? 0;
      if (count > bestCount) {
        bestCount = count;
        best = Evidence('Sentry', '${i['title']}',
            detail: '${i['culprit'] ?? 'unknown location'}, $count events',
            at: seen.toLocal(),
            url: i['permalink'] as String?);
      }
    }
    return best;
  }

  Future<Evidence?> _github(ProbeResult p) async {
    final since = p.at.subtract(const Duration(hours: 6)).toUtc().toIso8601String();
    final uri = Uri.https('api.github.com', '/repos/${s.ghRepo}/commits',
        {'since': since, 'per_page': '10'});
    final headers = {'Accept': 'application/vnd.github+json'};
    if (s.ghToken.isNotEmpty) headers['Authorization'] = 'Bearer ${s.ghToken}';
    final r = await http.get(uri, headers: headers).timeout(const Duration(seconds: 15));
    if (r.statusCode != 200) throw 'HTTP ${r.statusCode}';
    for (final c in (jsonDecode(r.body) as List)) {
      final when = DateTime.tryParse(c['commit']['committer']['date'] ?? '')?.toLocal();
      if (when == null || when.isAfter(p.at)) continue;
      final sha = (c['sha'] as String).substring(0, 7);
      final msg = (c['commit']['message'] as String).split('\n').first;
      return Evidence('GitHub', '$sha $msg', at: when, url: c['html_url'] as String?);
    }
    return null;
  }

  /// Sample data so the UI can be explored without credentials.
  static (ProbeResult, Diagnosis) demo() {
    final now = DateTime.now();
    final p = ProbeResult(url: Uri.parse('https://api.acme.com/checkout'), at: now)
      ..dnsMs = 12
      ..tlsDays = 41
      ..status = 504
      ..reason = 'Gateway Timeout'
      ..ttfbMs = 30200
      ..cdn = 'Cloudflare'
      ..tcpMs = 31
      ..tlsMs = 48
      ..ipMs['104.18.1.1'] = 31
      ..ipMs['104.18.2.2'] = null
      ..ipErr['104.18.2.2'] = 'Connection timed out'
      ..headers['cf-ray'] = 'demo'
      ..companions['/'] = 200
      ..companions['/health'] = 504
      ..repeats.addAll([504, 200, 504]);
    final d = Diagnosis()
      ..score = 85
      ..summary = 'PoolTimeoutError (checkout/cart.py:88) is the likely cause of the 504 Gateway Timeout. '
          'Latest deploy candidate: a3f91c Reduce Redis client reuse.'
      ..error = Evidence('Sentry', 'PoolTimeoutError: no free connection',
          detail: 'checkout/cart.py:88, 38 events', at: now.subtract(const Duration(seconds: 2)))
      ..commit = Evidence('GitHub', 'a3f91c Reduce Redis client reuse',
          at: now.subtract(const Duration(minutes: 12)));
    d.timeline
      ..add(d.commit!)
      ..add(d.error!)
      ..add(Evidence('Probe', p.headline, at: now));
    return (p, d);
  }
}
