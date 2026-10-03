import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'correlator.dart';
import 'evidence.dart';
import 'inspector.dart';
import 'main.dart' show bg, card, muted, amber, teal, blue, red, line, violet;
import 'pagecheck.dart';
import 'probe.dart';
import 'ui.dart';

class Report {
  Report(this.probe, this.findings, this.layer, this.backend);
  final ProbeResult probe;
  final List<Finding> findings;
  final String? layer;
  final Diagnosis? backend;

  int get problems => findings.where((f) => f.severity == 2).length;
  int get warnings => findings.where((f) => f.severity == 1).length;
  List<Finding> get possible => findings.where((f) => f.confidence == 0 && f.severity >= 1).toList();

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
          indicatorWeight: 2,
          labelColor: teal,
          unselectedLabelColor: muted,
          labelStyle: const TextStyle(fontFamily: 'Chakra', fontWeight: FontWeight.w700, fontSize: 14),
          unselectedLabelStyle: const TextStyle(fontFamily: 'Chakra', fontWeight: FontWeight.w500, fontSize: 14),
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

Widget _panel({required Widget child, Color? border, Color? fill, bool glow = false}) =>
    NeonPanel(accent: border, glow: glow, child: child);

Widget _heading(String t) => Padding(
      padding: const EdgeInsets.only(top: 22, bottom: 10),
      child: Row(children: [
        Container(width: 3, height: 14, color: teal),
        const SizedBox(width: 8),
        Text(sentence(t), style: const TextStyle(color: muted, fontSize: 14, fontWeight: FontWeight.w600)),
      ]),
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
        border: cfg.$2,
        glow: true,
        child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Container(
            padding: const EdgeInsets.all(8),
            decoration: BoxDecoration(
                shape: BoxShape.circle,
                border: Border.all(color: cfg.$2.withValues(alpha: 0.7)),
                boxShadow: [BoxShadow(color: cfg.$2.withValues(alpha: 0.35), blurRadius: 16)]),
            child: Icon(cfg.$1, color: cfg.$2, size: 30),
          ),
          const SizedBox(width: 14),
          Expanded(
            child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
              Text(cfg.$3, style: TextStyle(color: cfg.$2, fontWeight: FontWeight.w700, fontSize: 14, letterSpacing: 0.5)),
              const SizedBox(height: 4),
              Text(p.headline, style: const TextStyle(fontSize: 22, fontWeight: FontWeight.w700, height: 1.2)),
              if (report.layer != null && report.state != 'healthy') ...[
                const SizedBox(height: 10),
                Container(
                  padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 5),
                  decoration: ShapeDecoration(color: cfg.$2.withValues(alpha: 0.14), shape: cutShape(color: cfg.$2.withValues(alpha: 0.6), cut: 8)),
                  child: Text('Failing layer: ${report.layer}',
                      style: TextStyle(color: cfg.$2, fontSize: 12, fontWeight: FontWeight.w600)),
                ),
              ],
              if (p.cdn != null || p.server != null) ...[
                const SizedBox(height: 8),
                Text([if (p.cdn != null) p.cdn!, if (p.server != null) p.server!].join(' · '),
                    style: const TextStyle(color: muted, fontSize: 13, fontFamily: kMono)),
              ],
            ]),
          ),
        ]),
      ),
      if (main != null) ...[
        _heading('PRIMARY ISSUE'),
        ErrorCard(finding: main, collapsible: false),
      ] else if (steps != null) ...[
        _heading('WHAT TO TRY'),
        _panel(child: _Steps(steps)),
      ],
      if (report.possible.where((x) => x != main).isNotEmpty) ...[
        _heading('ALSO POSSIBLE'),
        for (final x in report.possible.where((x) => x != main).take(2)) ErrorCard(finding: x),
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
              decoration: ShapeDecoration(
                color: card,
                shape: cutShape(color: t.$3 ? amber.withValues(alpha: 0.6) : line, cut: 10),
              ),
              child: Column(mainAxisAlignment: MainAxisAlignment.center, crossAxisAlignment: CrossAxisAlignment.start, children: [
                Text(t.$1, style: const TextStyle(color: muted, fontSize: 13)),
                const SizedBox(height: 2),
                Text(t.$2, style: TextStyle(fontSize: 18, fontFamily: kMono, color: t.$3 ? amber : teal)),
              ]),
            ),
        ],
      ),
      if (report.backend != null && p.failed) ...[
        _heading('BACKEND CORRELATION'),
        InkWell(
          customBorder: cutShape(),
          onTap: () => Navigator.push(
              context, MaterialPageRoute(builder: (_) => EvidenceScreen(diagnosis: report.backend!))),
          child: _panel(
            border: violet,
            glow: true,
            child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
              Text('Score ${report.backend!.score}/100', style: const TextStyle(color: violet, fontSize: 16, fontFamily: kMono)),
              const SizedBox(height: 6),
              Text(report.backend!.summary, style: const TextStyle(fontSize: 15, height: 1.35)),
              const SizedBox(height: 8),
              const Text('View evidence', style: TextStyle(color: violet, fontWeight: FontWeight.w700)),
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

Widget _mini(String t) => Padding(
      padding: const EdgeInsets.only(top: 14, bottom: 6),
      child: Text(sentence(t), style: const TextStyle(color: muted, fontSize: 13, fontWeight: FontWeight.w600)),
    );

class _Steps extends StatelessWidget {
  const _Steps(this.steps);
  final List<String> steps;
  @override
  Widget build(BuildContext context) => Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
        for (var i = 0; i < steps.length; i++)
          Padding(
            padding: EdgeInsets.only(bottom: i == steps.length - 1 ? 0 : 10),
            child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
              Container(
                width: 22,
                height: 22,
                alignment: Alignment.center,
                decoration: BoxDecoration(shape: BoxShape.circle, border: Border.all(color: teal.withValues(alpha: 0.6))),
                child: Text('${i + 1}', style: const TextStyle(color: teal, fontSize: 12, fontFamily: kMono)),
              ),
              const SizedBox(width: 10),
              Expanded(child: Text(steps[i], style: const TextStyle(fontSize: 14, height: 1.35))),
            ]),
          ),
      ]);
}

class ErrorCard extends StatelessWidget {
  const ErrorCard({super.key, required this.finding, this.collapsible = true});
  final Finding finding;
  final bool collapsible;

  @override
  Widget build(BuildContext context) {
    final f = finding;
    final c = sevColor(f.severity);
    final confColor = f.confidence == 2 ? teal : (f.confidence == 1 ? blue : muted);
    Widget chip(String t, Color col) => Container(
          padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
          decoration: ShapeDecoration(color: col.withValues(alpha: 0.12), shape: cutShape(color: col.withValues(alpha: 0.5), cut: 6)),
          child: Text(t, style: TextStyle(color: col, fontSize: 12, fontFamily: kMono)),
        );
    final header = Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
      Icon(sevIcon(f.severity), color: c, size: 22),
      const SizedBox(width: 12),
      Expanded(
        child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Text(f.title, style: const TextStyle(fontWeight: FontWeight.w600, fontSize: 15, height: 1.25)),
          const SizedBox(height: 8),
          Wrap(spacing: 6, runSpacing: 6, children: [
            chip(sevName(f.severity), c),
            chip(confName(f.confidence), confColor),
            if (f.layer != null) chip(f.layer!, muted),
          ]),
        ]),
      ),
    ]);
    final fixes = f.severity == 0 ? null : (f.fixes ?? (f.layer == null ? null : layerSteps[f.layer]));
    final body = Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
      if (f.evidence != null && f.evidence!.isNotEmpty) ...[
        _mini('WHAT WE SAW'),
        Container(
          width: double.infinity,
          padding: const EdgeInsets.all(10),
          decoration: ShapeDecoration(color: bg, shape: cutShape(cut: 8)),
          child: SelectableText(f.evidence!, style: const TextStyle(fontFamily: kMono, fontSize: 13, height: 1.4, color: teal)),
        ),
      ],
      if (f.detail.isNotEmpty) ...[
        _mini(f.severity == 0 ? 'DETAILS' : 'WHAT IT MEANS'),
        Text(f.detail, style: const TextStyle(fontSize: 14, height: 1.4)),
      ],
      if (fixes != null && fixes.isNotEmpty) ...[
        _mini('HOW TO FIX'),
        _Steps(fixes),
      ],
      if (f.confidence < 2) ...[
        const SizedBox(height: 12),
        Text(
            f.confidence == 1
                ? 'The cause is inferred from the response. Confirm it in your app logs.'
                : 'Inferred from outside behaviour only. Confirm it in your app logs or Sentry.',
            style: const TextStyle(color: muted, fontSize: 12, height: 1.4)),
      ],
    ]);

    final decoration = ShapeDecoration(
      gradient: LinearGradient(begin: Alignment.topLeft, end: Alignment.bottomRight, colors: [c.withValues(alpha: 0.10), card]),
      shape: cutShape(color: c.withValues(alpha: f.severity == 0 ? 0.25 : 0.55), cut: 12),
    );
    if (!collapsible) {
      return Container(
        width: double.infinity,
        padding: const EdgeInsets.all(14),
        decoration: decoration,
        child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [header, body]),
      );
    }
    return Container(
      margin: const EdgeInsets.only(bottom: 8),
      decoration: decoration,
      child: Theme(
        data: Theme.of(context).copyWith(dividerColor: Colors.transparent),
        child: ExpansionTile(
          initiallyExpanded: f.severity == 2,
          shape: const Border(),
          collapsedShape: const Border(),
          tilePadding: const EdgeInsets.all(14),
          childrenPadding: const EdgeInsets.fromLTRB(14, 0, 14, 14),
          expandedCrossAxisAlignment: CrossAxisAlignment.start,
          title: header,
          children: [body],
        ),
      ),
    );
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
      out.add(_heading('${['INFO', 'WARNINGS', 'PROBLEMS'][sev]} (${items.length})'));
      for (final f in items) {
        out.add(ErrorCard(finding: f));
      }
    }
    if (report.findings.isEmpty) {
      out.add(const Padding(padding: EdgeInsets.all(24), child: Text('Nothing to report.', style: TextStyle(color: muted))));
    }
    out.add(_heading('WHAT THIS CHECK CANNOT SEE'));
    out.add(_panel(
      child: const Text(
        'Anything that only happens inside your servers: stack traces, slow queries, database timeouts, memory pressure.\n\n'
        'A database timeout shows up here only when the error page leaks its message (then it is Confirmed, with the text shown), '
        'or indirectly, through slow responses, one route failing while the rest works, or intermittent failures (then it is only Possible). '
        'To confirm it, check your app logs, or connect Sentry (optional).',
        style: TextStyle(color: muted, fontSize: 13, height: 1.45),
      ),
    ));
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
      if (p.tlsMs != null) ('TLS', p.tlsMs!, violet),
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
                            child: Container(
                                height: 8,
                                decoration: BoxDecoration(
                                    gradient: LinearGradient(colors: [s.$3.withValues(alpha: 0.4), s.$3]),
                                    borderRadius: BorderRadius.circular(2),
                                    boxShadow: [BoxShadow(color: s.$3.withValues(alpha: 0.5), blurRadius: 8)])),
                          ),
                        ),
                      ),
                      SizedBox(
                          width: 64,
                          child: Text('${s.$2} ms', textAlign: TextAlign.right, style: const TextStyle(fontFamily: kMono, fontSize: 13, color: muted))),
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
                  Expanded(child: Text(e.key, style: const TextStyle(fontFamily: kMono, fontSize: 14))),
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
                decoration: ShapeDecoration(
                    color: ((e.value ?? 999) >= 400 ? red : teal).withValues(alpha: 0.10),
                    shape: cutShape(color: ((e.value ?? 999) >= 400 ? red : teal).withValues(alpha: 0.5), cut: 8)),
                child: Text('${e.key}  ${e.value ?? 'no reply'}',
                    style: TextStyle(fontFamily: kMono, fontSize: 13, color: (e.value ?? 999) >= 400 ? red : teal)),
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
            style: const TextStyle(fontFamily: kMono, fontSize: 12, color: muted, height: 1.5),
          ),
        ),
      ],
    ]);
  }
}
