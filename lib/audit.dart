import 'dart:async';
import 'dart:io';

class AssetIssue {
  AssetIssue(this.url, this.kind, this.problem, this.severity);
  final String url;
  final String kind;
  final String problem;
  final int severity;
}

class AuditResult {
  AuditResult(this.total, this.issues);
  final int total;
  final List<AssetIssue> issues;
}

/// Finds scripts, stylesheets and images in the page HTML and checks that each one loads.
Future<AuditResult?> auditAssets(Uri base, String html) async {
  final found = <String, String>{};
  void add(String kind, String? raw) {
    if (raw == null) return;
    final v = raw.trim();
    if (v.isEmpty ||
        v.startsWith('data:') ||
        v.startsWith('javascript:') ||
        v.startsWith('#') ||
        v.startsWith('mailto:') ||
        v.startsWith('blob:')) {
      return;
    }
    Uri u;
    try {
      u = base.resolve(v);
    } catch (_) {
      return;
    }
    if (u.scheme != 'http' && u.scheme != 'https') return;
    found.putIfAbsent(u.toString(), () => kind);
  }

  for (final m in RegExp(r'''<script[^>]*?\ssrc=["']([^"']+)["']''', caseSensitive: false).allMatches(html)) {
    add('script', m.group(1));
  }
  for (final m in RegExp(r'''<link[^>]*?rel=["']stylesheet["'][^>]*?href=["']([^"']+)["']''', caseSensitive: false).allMatches(html)) {
    add('stylesheet', m.group(1));
  }
  for (final m in RegExp(r'''<link[^>]*?href=["']([^"']+)["'][^>]*?rel=["']stylesheet["']''', caseSensitive: false).allMatches(html)) {
    add('stylesheet', m.group(1));
  }
  for (final m in RegExp(r'''<img[^>]*?\ssrc=["']([^"']+)["']''', caseSensitive: false).allMatches(html)) {
    add('image', m.group(1));
  }

  final items = found.entries.take(25).toList();
  if (items.isEmpty) return AuditResult(0, []);

  final client = HttpClient()..connectionTimeout = const Duration(seconds: 6);
  final issues = <AssetIssue>[];
  await Future.wait(items.map((e) async {
    final u = Uri.parse(e.key);
    final kind = e.value;
    final critical = kind != 'image';
    if (base.scheme == 'https' && u.scheme == 'http') {
      issues.add(AssetIssue(e.key, kind, 'Mixed content (browsers block it)', 1));
    }
    final sw = Stopwatch()..start();
    try {
      final req = await client.getUrl(u);
      req.headers.set('user-agent', 'PingR/0.5');
      final resp = await req.close().timeout(const Duration(seconds: 8));
      await resp.drain<void>().timeout(const Duration(seconds: 8));
      final code = resp.statusCode;
      final thirdParty = u.host != base.host;
      final ambiguous = thirdParty && (code == 401 || code == 403 || code == 405 || code == 429);
      if (code >= 400 && !ambiguous) {
        issues.add(AssetIssue(e.key, kind, 'HTTP $code', critical ? 2 : 1));
      } else if (sw.elapsedMilliseconds > 3000) {
        issues.add(AssetIssue(e.key, kind, 'Slow (${sw.elapsedMilliseconds}ms)', 1));
      }
    } catch (_) {
      issues.add(AssetIssue(e.key, kind, 'Failed to load', critical ? 2 : 1));
    }
  }));
  client.close(force: true);
  return AuditResult(items.length, issues);
}
