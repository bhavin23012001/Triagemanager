import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'correlator.dart';
import 'evidence.dart';
import 'inspector.dart';
import 'main.dart' show card, muted, amber, teal, blue, red, line;
import 'pagecheck.dart';
import 'probe.dart';

class Report {
  Report(this.probe, this.findings, this.layer, this.backend);
  final ProbeResult probe;
  final List<Finding> findings;
  final String? layer;
  final Diagnosis? backend;

  int get problems => findings.where((f) => f.severity == 2).length;
  int get warnings => findings.where((f) => f.severity == 1).length;

  String get state {
    if (probe.failed) return 'down';
    if (problems > 0) return 'problems';
    if (warnings > 0) return 'warnings';
    return 'healthy';
  }

  Finding? get mainFinding {
    for (final sev in [2, 1]) {
      for (final f in findings) {
        if (f.severity == sev && f.layer == layer && f.detail.isNotEmpty) return f;
      }
    }
    for (final f in findings) {
      if (f.severity >= 1 && f.detail.isNotEmpty) return f;
    }
    return null;
  }
}

Color sevColor(int s) => s == 2 ? red : (s == 1 ? amber : blue);
IconData sevIcon(int s) =>
    s == 2 ? Icons.error_rounded : (s == 1 ? Icons.warning_amber_rounded : Icons.info_outline_rounded);
String sevName(int s) => s == 2 ? 'Problem' : (s == 1 ? 'Warning' : 'Info');

class ResultView extends StatelessWidget {
  const ResultView({super.key, required this.report, required this.onOpenSettings});
  final Report report;
  final VoidCallback onOpenSettings;

  @override
  Widget build(BuildContext context) {
    final n = report.problems + report.warnings;
    return DefaultTabController(
      length: 3,
      child: Column(children: [
        TabBar(
          indicatorColor: teal,
          labelColor: teal,
          unselectedLabelColor: muted,
          tabs: [
            const Tab(text: 'Summary'),
            Tab(text: n > 0 ? 'Findings ($n)' : 'Findings'),
            const Tab(text: 'Network'),
          ],
        ),
        Expanded(
          child: TabBarView(children: [
            _Summary(report: report, onOpenSettings: onOpenSettings),
            _Findings(report: report),
            _Network(report: report),
          ]),
        ),
      ]),
    );
  }
}

Widget _panel({required Widget child, Color? border, Color? fill}) => Container(
      width: double.infinity,
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: fill ?? card,
        borderRadius: BorderRadius.circular(16),
        border: Border.all(color: border ?? line),
      ),
      child: child,
    );

Widget _heading(String t) => Padding(
      padding: const EdgeInsets.only(top: 20, bottom: 8),
      child: Text(t, style: const TextStyle(color: muted, fontSize: 12, letterSpacing: 1, fontWeight: FontWeight.w600)),
    );

class _Summary extends StatelessWidget {
  const _Summary({required this.report, required this.onOpenSettings});
  final Report report;
  final VoidCallback onOpenSettings;

  @override
  Widget build(BuildContext context) {
    final p = report.probe;
    final cfg = switch (report.state) {
      'down' => (Icons.cancel_rounded, red, 'Not working'),
      'problems' => (Icons.error_rounded, amber, 'Working, with problems'),
      'warnings' => (Icons.warning_amber_rounded, amber, 'Working, with warnings'),
      _ => (Icons.check_circle_rounded, teal, 'Healthy'),
    };
    final main = report.mainFinding;
    final steps = report.layer == null ? null : layerSteps[report.layer];
    final tiles = <(String, String, bool)>[
      ('Status', p.status != null ? '${p.status}' : 'No reply', p.status == null || p.status! >= 500),
      ('DNS', p.dnsError != null ? 'Failed' : '${p.dnsMs ?? '-'} ms', p.dnsError != null),
      ('Connect', p.tcpMs != null ? '${p.tcpMs} ms' : 'Failed', p.tcpMs == null && p.dnsError == null),
      ('Certificate', p.tlsError != null ? 'Invalid' : (p.tlsDays != null ? '${p.tlsDays} days left' : 'n/a'), p.tlsError != null),
      ('First byte', p.ttfbMs != null ? '${p.ttfbMs} ms' : '-', (p.ttfbMs ?? 0) > 3000),
      ('Total', p.totalMs != null ? '${p.totalMs} ms' : '-', false),
    ];

    return ListView(padding: const EdgeInsets.fromLTRB(16, 8, 16, 32), children: [
      const SizedBox(height: 8),
      _panel(
        border: cfg.$2.withValues(alpha: 0.5),
        child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Icon(cfg.$1, color: cfg.$2, size: 40),
          const SizedBox(width: 14),
          Expanded(
            child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
              Text(cfg.$3, style: TextStyle(color: cfg.$2, fontWeight: FontWeight.w700, fontSize: 13)),
              const SizedBox(height: 4),
              Text(p.headline, style: const TextStyle(fontSize: 22, fontWeight: FontWeight.w700, height: 1.2)),
              if (report.layer != null && report.state != 'healthy') ...[
                const SizedBox(height: 10),
                Container(
                  padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 5),
                  decoration: BoxDecoration(color: cfg.$2.withValues(alpha: 0.15), borderRadius: BorderRadius.circular(20)),
                  child: Text('Failing layer: ${report.layer}',
                      style: TextStyle(color: cfg.$2, fontSize: 12, fontWeight: FontWeight.w600)),
                ),
              ],
              if (p.cdn != null || p.server != null) ...[
                const SizedBox(height: 8),
                Text([if (p.cdn != null) p.cdn!, if (p.server != null) p.server!].join(' · '),
                    style: const TextStyle(color: muted, fontSize: 12)),
              ],
            ]),
          ),
        ]),
      ),
      if (main != null) ...[
        _heading('WHAT THIS MEANS'),
        _panel(child: Text('${main.title}. ${main.detail}', style: const TextStyle(fontSize: 15, height: 1.4))),
      ],
      if (steps != null) ...[
        _heading('WHAT TO TRY'),
        _panel(
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            for (var i = 0; i < steps.length; i++)
              Padding(
                padding: EdgeInsets.only(bottom: i == steps.length - 1 ? 0 : 10),
                child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
                  Container(
                    width: 24,
                    height: 24,
                    alignment: Alignment.center,
                    decoration: BoxDecoration(color: teal.withValues(alpha: 0.15), shape: BoxShape.circle),
                    child: Text('${i + 1}', style: const TextStyle(color: teal, fontSize: 12, fontWeight: FontWeight.w700)),
                  ),
                  const SizedBox(width: 12),
                  Expanded(child: Text(steps[i], style: const TextStyle(fontSize: 14, height: 1.35))),
                ]),
              ),
          ]),
        ),
      ],
      _heading('KEY NUMBERS'),
      GridView.count(
        crossAxisCount: 2,
        shrinkWrap: true,
        physics: const NeverScrollableScrollPhysics(),
        mainAxisSpacing: 8,
        crossAxisSpacing: 8,
        childAspectRatio: 2.4,
        children: [
          for (final t in tiles)
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
              decoration: BoxDecoration(color: card, borderRadius: BorderRadius.circular(14), border: Border.all(color: line)),
              child: Column(mainAxisAlignment: MainAxisAlignment.center, crossAxisAlignment: CrossAxisAlignment.start, children: [
                Text(t.$1, style: const TextStyle(color: muted, fontSize: 12)),
                const SizedBox(height: 2),
                Text(t.$2, style: TextStyle(fontSize: 16, fontWeight: FontWeight.w600, color: t.$3 ? amber : null)),
              ]),
            ),
        ],
      ),
      if (report.backend != null && p.failed) ...[
        _heading('BACKEND CORRELATION'),
        InkWell(
          borderRadius: BorderRadius.circular(16),
          onTap: () => Navigator.push(
              context, MaterialPageRoute(builder: (_) => EvidenceScreen(diagnosis: report.backend!))),
          child: _panel(
            border: const Color(0xFF1F6B55),
            fill: const Color(0xFF10261F),
            child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
              Text('SCORE ${report.backend!.score}/100', style: const TextStyle(color: teal, fontSize: 12, fontWeight: FontWeight.w700)),
              const SizedBox(height: 6),
              Text(report.backend!.summary, style: const TextStyle(fontSize: 15, height: 1.35)),
              const SizedBox(height: 8),
              const Text('View evidence', style: TextStyle(color: teal, fontWeight: FontWeight.w600)),
            ]),
          ),
        ),
      ],
      const SizedBox(height: 16),
      Row(children: [
        Expanded(
          child: SizedBox(
            height: 48,
            child: OutlinedButton.icon(
              icon: const Icon(Icons.copy_rounded, size: 18),
              label: const Text('Copy report'),
              onPressed: () {
                Clipboard.setData(ClipboardData(text: buildReport(p, report.findings, report.layer)));
                ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text('Report copied')));
              },
            ),
          ),
        ),
        const SizedBox(width: 8),
        Expanded(
          child: SizedBox(
            height: 48,
            child: OutlinedButton.icon(
              icon: const Icon(Icons.web_rounded, size: 18),
              label: const Text('Test in browser'),
              onPressed: () => Navigator.push(
                  context, MaterialPageRoute(builder: (_) => PageCheckScreen(url: p.url.toString()))),
            ),
          ),
        ),
      ]),
      if (report.backend == null) ...[
        const SizedBox(height: 16),
        TextButton(
          onPressed: onOpenSettings,
          child: const Text('Optional: link failures to backend errors (Sentry, GitHub)'),
        ),
      ],
    ]);
  }
}

class _Findings extends StatelessWidget {
  const _Findings({required this.report});
  final Report report;

  @override
  Widget build(BuildContext context) {
    final out = <Widget>[const SizedBox(height: 8)];
    for (final sev in [2, 1, 0]) {
      final items = report.findings.where((f) => f.severity == sev).toList();
      if (items.isEmpty) continue;
      out.add(_heading('${sevName(sev).toUpperCase()}S (${items.length})'));
      for (final f in items) {
        out.add(Container(
          width: double.infinity,
          margin: const EdgeInsets.only(bottom: 8),
          padding: const EdgeInsets.all(14),
          decoration: BoxDecoration(
              color: card, borderRadius: BorderRadius.circular(14), border: Border.all(color: line)),
          child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Icon(sevIcon(sev), color: sevColor(sev), size: 22),
            const SizedBox(width: 12),
            Expanded(
              child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                Text(f.title, style: const TextStyle(fontWeight: FontWeight.w600, fontSize: 15)),
                if (f.detail.isNotEmpty) ...[
                  const SizedBox(height: 4),
                  Text(f.detail, style: const TextStyle(color: muted, fontSize: 13, height: 1.35)),
                ],
                if (f.layer != null) ...[
                  const SizedBox(height: 8),
                  Text(f.layer!, style: TextStyle(color: sevColor(sev), fontSize: 11, fontWeight: FontWeight.w600)),
                ],
              ]),
            ),
          ]),
        ));
      }
    }
    if (report.findings.isEmpty) {
      out.add(const Padding(padding: EdgeInsets.all(24), child: Text('Nothing to report.', style: TextStyle(color: muted))));
    }
    out.add(const SizedBox(height: 24));
    return ListView(padding: const EdgeInsets.symmetric(horizontal: 16), children: out);
  }
}

class _Network extends StatelessWidget {
  const _Network({required this.report});
  final Report report;

  @override
  Widget build(BuildContext context) {
    final p = report.probe;
    final wait = (p.ttfbMs ?? 0) - (p.tcpMs ?? 0) - (p.tlsMs ?? 0);
    final segs = <(String, int, Color)>[
      if (p.dnsMs != null) ('DNS', p.dnsMs!, blue),
      if (p.tcpMs != null) ('Connect', p.tcpMs!, teal),
      if (p.tlsMs != null) ('TLS', p.tlsMs!, const Color(0xFFB392F0)),
      if (p.ttfbMs != null) ('Server wait', wait < 0 ? 0 : wait, amber),
      if (p.totalMs != null && p.ttfbMs != null) ('Download', p.totalMs! - p.ttfbMs!, const Color(0xFF79C0FF)),
    ];
    final maxMs = segs.isEmpty ? 1 : segs.map((s) => s.$2).reduce((a, b) => a > b ? a : b).clamp(1, 1 << 30);

    return ListView(padding: const EdgeInsets.fromLTRB(16, 8, 16, 32), children: [
      _heading('TIMING'),
      _panel(
        child: segs.isEmpty
            ? const Text('No timing data: the request did not get that far.', style: TextStyle(color: muted))
            : Column(children: [
                for (final s in segs)
                  Padding(
                    padding: const EdgeInsets.symmetric(vertical: 6),
                    child: Row(children: [
                      SizedBox(width: 92, child: Text(s.$1, style: const TextStyle(fontSize: 13))),
                      Expanded(
                        child: Align(
                          alignment: Alignment.centerLeft,
                          child: FractionallySizedBox(
                            widthFactor: (s.$2 / maxMs).clamp(0.02, 1.0).toDouble(),
                            child: Container(height: 10, decoration: BoxDecoration(color: s.$3, borderRadius: BorderRadius.circular(5))),
                          ),
                        ),
                      ),
                      SizedBox(
                          width: 64,
                          child: Text('${s.$2} ms', textAlign: TextAlign.right, style: const TextStyle(fontFamily: 'monospace', fontSize: 12, color: muted))),
                    ]),
                  ),
              ]),
      ),
      if (p.ipMs.isNotEmpty) ...[
        _heading('SERVERS BEHIND THIS NAME'),
        _panel(
          child: Column(children: [
            for (final e in p.ipMs.entries)
              Padding(
                padding: const EdgeInsets.symmetric(vertical: 5),
                child: Row(children: [
                  Icon(e.value != null ? Icons.check_circle_rounded : Icons.cancel_rounded,
                      size: 18, color: e.value != null ? teal : red),
                  const SizedBox(width: 10),
                  Expanded(child: Text(e.key, style: const TextStyle(fontFamily: 'monospace', fontSize: 12))),
                  Text(e.value != null ? '${e.value} ms' : (p.ipErr[e.key] ?? 'failed'),
                      style: TextStyle(fontSize: 12, color: e.value != null ? muted : red)),
                ]),
              ),
          ]),
        ),
      ],
      if (p.companions.isNotEmpty) ...[
        _heading('OTHER PATHS ON THE SAME HOST'),
        _panel(
          child: Wrap(spacing: 8, runSpacing: 8, children: [
            for (final e in p.companions.entries)
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
                decoration: BoxDecoration(
                    color: ((e.value ?? 999) >= 400 ? red : teal).withValues(alpha: 0.12),
                    borderRadius: BorderRadius.circular(10)),
                child: Text('${e.key}  ${e.value ?? 'no reply'}',
                    style: TextStyle(fontFamily: 'monospace', fontSize: 12, color: (e.value ?? 999) >= 400 ? red : teal)),
              ),
          ]),
        ),
      ],
      if (p.tlsIssuer != null || p.tlsDays != null) ...[
        _heading('CERTIFICATE'),
        _panel(
          child: Text(
              '${p.tlsIssuer != null ? 'Issuer: ${p.tlsIssuer}\n' : ''}${p.tlsDays != null ? 'Expires in ${p.tlsDays} days' : ''}',
              style: const TextStyle(fontSize: 13, height: 1.4)),
        ),
      ],
      if (p.headers.isNotEmpty) ...[
        _heading('RESPONSE HEADERS'),
        _panel(
          child: SelectableText(
            p.headers.entries.map((e) => '${e.key}: ${e.value}').join('\n'),
            style: const TextStyle(fontFamily: 'monospace', fontSize: 11, color: muted, height: 1.5),
          ),
        ),
      ],
    ]);
  }
}
