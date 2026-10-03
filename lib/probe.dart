import 'dart:async';
import 'dart:convert';
import 'dart:io';

class ProbeResult {
  ProbeResult({required this.url, required this.at});
  final Uri url;
  final DateTime at;
  int? dnsMs;
  String? dnsError;
  List<InternetAddress> addrs = [];
  final Map<String, int?> ipMs = {};
  final Map<String, String> ipErr = {};
  int? tcpMs;
  int? tlsMs;
  int? tlsDays;
  String? tlsError;
  String? tlsIssuer;
  DateTime? tlsStart;
  int? status;
  String? reason;
  int? ttfbMs;
  int? totalMs;
  String? httpError;
  String? bodyError;
  bool truncated = false;
  String? server;
  String? cdn;
  String? contentType;
  String body = '';
  final Map<String, String> headers = {};
  final List<String> redirects = [];
  final List<int?> repeats = [];
  final Map<String, int?> companions = {};

  bool get failed =>
      dnsError != null ||
      tlsError != null ||
      httpError != null ||
      truncated ||
      (status ?? 0) >= 500;

  String get headline {
    if (dnsError != null) return 'DNS: $dnsError';
    if (tlsError != null) return 'TLS: $tlsError';
    if (httpError != null) return httpError!;
    if (truncated) return 'Response cut off';
    return '$status ${reason ?? ''}'.trim();
  }
}

class Prober {
  static Future<ProbeResult> run(String input,
      {Duration timeout = const Duration(seconds: 30)}) async {
    final t = input.trim();
    final uri = Uri.tryParse(t.contains('://') ? t : 'https://$t') ?? Uri();
    final r = ProbeResult(url: uri, at: DateTime.now());
    if (uri.host.isEmpty) {
      r.dnsError = 'Invalid URL';
      return r;
    }
    final port = uri.hasPort ? uri.port : (uri.scheme == 'https' ? 443 : 80);

    var sw = Stopwatch()..start();
    try {
      r.addrs = await InternetAddress.lookup(uri.host).timeout(const Duration(seconds: 10));
      r.dnsMs = sw.elapsedMilliseconds;
    } catch (e) {
      r.dnsError = friendly(e);
      return r;
    }

    // Check every address separately: one dead server behind DNS causes random failures.
    await Future.wait(r.addrs.take(4).map((a) async {
      final s = Stopwatch()..start();
      try {
        final sock = await Socket.connect(a, port, timeout: const Duration(seconds: 6));
        sock.destroy();
        r.ipMs[a.address] = s.elapsedMilliseconds;
      } catch (e) {
        r.ipMs[a.address] = null;
        r.ipErr[a.address] = friendly(e);
      }
    }));
    final okMs = r.ipMs.values.whereType<int>().toList();
    if (okMs.isEmpty) {
      r.httpError = r.ipErr.values.first;
      return r;
    }
    r.tcpMs = okMs.reduce((a, b) => a < b ? a : b);

    if (uri.scheme == 'https') {
      sw = Stopwatch()..start();
      try {
        final s = await SecureSocket.connect(uri.host, port, timeout: const Duration(seconds: 10));
        final ms = sw.elapsedMilliseconds - r.tcpMs!;
        r.tlsMs = ms < 0 ? 0 : ms;
        final c = s.peerCertificate;
        if (c != null) {
          r.tlsDays = c.endValidity.difference(DateTime.now()).inDays;
          r.tlsIssuer = c.issuer;
          r.tlsStart = c.startValidity;
        }
        s.destroy();
      } catch (e) {
        r.tlsError = friendly(e);
        return r;
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
        req.headers.set('user-agent', 'TriageAgent/0.2');
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
        r.contentType = fr.headers.contentType?.mimeType;
        fr.headers.forEach((name, values) => r.headers[name.toLowerCase()] = values.join(', '));
        if (r.headers.containsKey('cf-ray')) {
          r.cdn = 'Cloudflare';
        } else if (r.headers.containsKey('x-amz-cf-id')) {
          r.cdn = 'CloudFront';
        } else if (r.headers.containsKey('x-vercel-id')) {
          r.cdn = 'Vercel';
        }
        final bytes = <int>[];
        try {
          await for (final chunk in fr.timeout(timeout)) {
            if (bytes.length < 65536) bytes.addAll(chunk);
          }
        } catch (e) {
          r.truncated = true;
          r.bodyError = friendly(e);
        }
        r.body = utf8.decode(bytes, allowMalformed: true);
        r.totalMs = sw.elapsedMilliseconds;
      }
    } on TimeoutException {
      r.httpError = 'Timed out after ${timeout.inSeconds}s';
    } catch (e) {
      r.httpError = friendly(e);
    } finally {
      client.close(force: true);
    }

    // Repeat the request and try nearby paths in parallel.
    r.repeats.add(r.status);
    final paths = ['/', '/health', '/healthz', '/robots.txt']
        .where((p) => p != uri.path && !(p == '/' && uri.path.isEmpty))
        .toList();
    final reps = Future.wait([_once(uri), _once(uri)]);
    final comps = Future.wait(paths.map((p) => _once(_base(uri, p))));
    r.repeats.addAll(await reps);
    final res = await comps;
    for (var i = 0; i < paths.length; i++) {
      r.companions[paths[i]] = res[i];
    }
    return r;
  }

  static Uri _base(Uri u, String path) => Uri(
        scheme: u.scheme,
        host: u.host,
        port: u.hasPort ? u.port : null,
        path: path,
      );

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

  static String friendly(Object e) {
    if (e is TimeoutException) return 'Timed out';
    final m = e.toString().toLowerCase();
    if (e is HandshakeException || e is TlsException) {
      if (m.contains('expired')) return 'Certificate expired';
      if (m.contains('hostname') || m.contains('host name')) return 'Certificate does not match the hostname';
      if (m.contains('self') && m.contains('signed')) return 'Self-signed certificate';
      if (m.contains('issuer') || m.contains('unknown ca') || m.contains('unable to get')) {
        return 'Untrusted or incomplete certificate chain';
      }
      if (m.contains('protocol') || m.contains('version')) return 'TLS protocol or version mismatch';
      return 'TLS handshake failed';
    }
    if (e is SocketException) {
      final code = e.osError?.errorCode;
      if (m.contains('refused') || code == 111 || code == 61 || code == 10061) {
        return 'Connection refused (nothing is listening)';
      }
      if (m.contains('timed out') || code == 110 || code == 60 || code == 10060) {
        return 'Connection timed out';
      }
      if (m.contains('reset') || code == 104 || code == 54 || code == 10054) {
        return 'Connection reset by peer';
      }
      if (m.contains('no route') || code == 113 || code == 65) return 'No route to host';
      if (m.contains('unreachable') || code == 101 || code == 51) return 'Network unreachable';
      if (m.contains('host lookup') || m.contains('no address')) return 'DNS lookup failed';
      if (m.contains('broken pipe')) return 'Broken pipe';
      return 'Socket error';
    }
    if (e is HttpException) {
      if (m.contains('connection closed')) return 'Connection closed before the full response arrived';
      return 'HTTP protocol error';
    }
    final s = e.toString();
    return s.length > 80 ? '${s.substring(0, 80)}...' : s;
  }
}
