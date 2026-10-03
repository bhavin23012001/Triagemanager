import 'dart:async';
import 'dart:convert';
import 'dart:io';

class ProbeResult {
  ProbeResult({required this.url, required this.at});
  final Uri url;
  final DateTime at;
  int? dnsMs;
  String? dnsError;
  int? tlsDays;
  String? tlsError;
  int? status;
  String? reason;
  int? ttfbMs;
  int? totalMs;
  String? httpError;
  String? server;
  String? cdn;
  final Map<String, String> headers = {};
  String body = '';
  final List<String> redirects = [];
  final List<int?> repeats = [];

  bool get failed =>
      dnsError != null || tlsError != null || httpError != null || (status ?? 0) >= 500;

  String get headline {
    if (dnsError != null) return 'DNS resolution failed';
    if (tlsError != null) return 'TLS handshake failed';
    if (httpError != null) return httpError!;
    return '$status ${reason ?? ''}'.trim();
  }
}

class Prober {
  static Future<ProbeResult> run(String input,
      {Duration timeout = const Duration(seconds: 30)}) async {
    final t = input.trim();
    final uri = Uri.parse(t.contains('://') ? t : 'https://$t');
    final r = ProbeResult(url: uri, at: DateTime.now());

    var sw = Stopwatch()..start();
    try {
      await InternetAddress.lookup(uri.host).timeout(const Duration(seconds: 10));
      r.dnsMs = sw.elapsedMilliseconds;
    } catch (e) {
      r.dnsError = _short(e);
      return r;
    }

    if (uri.scheme == 'https') {
      try {
        final s = await SecureSocket.connect(uri.host, uri.hasPort ? uri.port : 443,
            timeout: const Duration(seconds: 10));
        final c = s.peerCertificate;
        if (c != null) r.tlsDays = c.endValidity.difference(DateTime.now()).inDays;
        s.destroy();
      } catch (e) {
        r.tlsError = _short(e);
      }
    }

    final client = HttpClient()..connectionTimeout = const Duration(seconds: 10);
    sw = Stopwatch()..start();
    try {
      var current = uri;
      HttpClientResponse? resp;
      for (var hop = 0; hop < 6; hop++) {
        final req = await client.getUrl(current);
        req.followRedirects = false;
        req.headers.set('user-agent', 'TriageAgent/0.1');
        resp = await req.close().timeout(timeout);
        final loc = resp.headers.value('location');
        if (resp.isRedirect && loc != null) {
          r.redirects.add('${resp.statusCode} -> $loc');
          await resp.drain<void>().timeout(timeout);
          if (hop == 5) {
            r.httpError = 'Too many redirects (possible loop)';
            resp = null;
            break;
          }
          current = current.resolve(loc);
          continue;
        }
        break;
      }
      final fr = resp;
      if (fr != null) {
        r.ttfbMs = sw.elapsedMilliseconds;
        r.status = fr.statusCode;
        r.reason = fr.reasonPhrase;
        r.server = fr.headers.value('server');
        fr.headers.forEach((name, values) => r.headers[name.toLowerCase()] = values.join(', '));
        if (r.headers.containsKey('cf-ray')) {
          r.cdn = 'Cloudflare';
        } else if (r.headers.containsKey('x-amz-cf-id')) {
          r.cdn = 'CloudFront';
        }
        final bytes = <int>[];
        await for (final chunk in fr.timeout(timeout)) {
          if (bytes.length < 65536) bytes.addAll(chunk);
        }
        r.body = utf8.decode(bytes, allowMalformed: true);
        r.totalMs = sw.elapsedMilliseconds;
      }
    } on TimeoutException {
      r.httpError = 'Timed out after ${timeout.inSeconds}s';
    } catch (e) {
      r.httpError = _short(e);
    } finally {
      client.close(force: true);
    }

    r.repeats.add(r.status);
    for (var i = 0; i < 2; i++) {
      r.repeats.add(await _once(uri));
    }
    return r;
  }

  static Future<int?> _once(Uri uri) async {
    final c = HttpClient()..connectionTimeout = const Duration(seconds: 8);
    try {
      final req = await c.getUrl(uri);
      final resp = await req.close().timeout(const Duration(seconds: 10));
      await resp.drain<void>().timeout(const Duration(seconds: 10));
      return resp.statusCode;
    } catch (_) {
      return null;
    } finally {
      c.close(force: true);
    }
  }

  static String _short(Object e) {
    final s = e.toString();
    return s.length > 90 ? '${s.substring(0, 90)}...' : s;
  }
}
