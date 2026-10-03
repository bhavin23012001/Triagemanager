import 'dart:async';
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
      final req = await client.getUrl(uri);
      req.headers.set('user-agent', 'TriageAgent/0.1');
      final resp = await req.close().timeout(timeout);
      r.ttfbMs = sw.elapsedMilliseconds;
      r.status = resp.statusCode;
      r.reason = resp.reasonPhrase;
      r.server = resp.headers.value('server');
      if (resp.headers.value('cf-ray') != null) {
        r.cdn = 'Cloudflare';
      } else if (resp.headers.value('x-amz-cf-id') != null) {
        r.cdn = 'CloudFront';
      }
      await resp.drain<void>().timeout(timeout);
      r.totalMs = sw.elapsedMilliseconds;
    } on TimeoutException {
      r.httpError = 'Timed out after ${timeout.inSeconds}s';
    } catch (e) {
      r.httpError = _short(e);
    } finally {
      client.close(force: true);
    }
    return r;
  }

  static String _short(Object e) {
    final s = e.toString();
    return s.length > 90 ? '${s.substring(0, 90)}...' : s;
  }
}
