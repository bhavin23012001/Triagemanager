import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'correlator.dart';
import 'evidence.dart';
import 'inspector.dart';
import 'pagecheck.dart';
import 'probe.dart';
import 'settings.dart';

const bg = Color(0xFF0E1116);
const card = Color(0xFF161B22);
const muted = Color(0xFF9AA7B5);
const amber = Color(0xFFF5B14A);
const teal = Color(0xFF4FD6B0);
const blue = Color(0xFF7FB5FF);

void main() => runApp(const TriageApp());

class TriageApp extends StatelessWidget {
  const TriageApp({super.key});
  @override
  Widget build(BuildContext context) => MaterialApp(
        title: 'Triage Agent',
        debugShowCheckedModeBanner: false,
        theme: ThemeData.dark(useMaterial3: true).copyWith(
          scaffoldBackgroundColor: bg,
          appBarTheme: const AppBarTheme(backgroundColor: bg),
          colorScheme: const ColorScheme.dark(primary: teal),
        ),
        home: const HomeScreen(),
      );
}

class HomeScreen extends StatefulWidget {
  const HomeScreen({super.key});
  @override
  State<HomeScreen> createState() => _HomeScreenState();
}

class _HomeScreenState extends State<HomeScreen> {
  final url = TextEditingController();
  Settings settings = Settings();
  ProbeResult? probe;
  Diagnosis? diagnosis;
  List<Finding> findings = [];
  String? layer;
  bool busy = false;
  List<String> recent = [];

  @override
  void initState() {
    super.initState();
    Settings.load().then((s) => setState(() => settings = s));
    SharedPreferences.getInstance()
        .then((p) => setState(() => recent = p.getStringList('recent') ?? []));
  }

  Future<void> _run() async {
    if (url.text.trim().isEmpty) return;
    setState(() => busy = true);
    final p = await Prober.run(url.text);
    final d = await Correlator(settings).diagnose(p);
    final f = inspect(p);
    final v = verdict(f);
    final prefs = await SharedPreferences.getInstance();
    final entry = '${p.url}\t${p.at.toIso8601String()}\t${p.headline}';
    final list = [entry, ...recent.where((e) => !e.startsWith('${p.url}\t'))].take(8).toList();
    await prefs.setStringList('recent', list);
    if (mounted) {
      setState(() {
        probe = p;
        diagnosis = d;
        findings = f;
        layer = v;
        recent = list;
        busy = false;
      });
    }
  }

  void _demo() {
    final (p, d) = Correlator.demo();
    final f = inspect(p);
    setState(() {
      url.text = p.url.toString();
      probe = p;
      diagnosis = d;
      findings = f;
      layer = verdict(f);
    });
  }

  Widget _check(String label, String value, {bool bad = false}) => Expanded(
        child: Container(
          padding: const EdgeInsets.all(12),
          decoration: BoxDecoration(color: card, borderRadius: BorderRadius.circular(12)),
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Text(label, style: const TextStyle(color: muted, fontSize: 12)),
            const SizedBox(height: 2),
            Text(value, style: TextStyle(fontFamily: 'monospace', fontSize: 14, color: bad ? amber : null)),
          ]),
        ),
      );

  Widget _row(Widget a, Widget b) => Padding(
        padding: const EdgeInsets.only(bottom: 8),
        child: Row(children: [a, const SizedBox(width: 8), b]),
      );

  Widget _label(String t) => Padding(
        padding: const EdgeInsets.only(top: 8, bottom: 8),
        child: Text(t, style: const TextStyle(color: muted, fontSize: 12, letterSpacing: 1)),
      );

  String _t(DateTime? t) => t == null
      ? ''
      : '${t.hour.toString().padLeft(2, '0')}:${t.minute.toString().padLeft(2, '0')}:${t.second.toString().padLeft(2, '0')}';

  List<Widget> _results(ProbeResult p, Diagnosis d) {
    final failed = p.failed;
    final httpBad = failed && p.dnsError == null && p.tlsError == null && p.ipMs.values.any((v) => v != null);
    return [
      Container(
        padding: const EdgeInsets.all(16),
        decoration: BoxDecoration(
            color: failed ? const Color(0xFF2B1D0A) : const Color(0xFF10261F),
            border: Border.all(color: failed ? const Color(0xFF7A4E0E) : const Color(0xFF1F6B55)),
            borderRadius: BorderRadius.circular(16)),
        child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Text(
              failed
                  ? 'FAILING LAYER: ${(layer ?? 'unknown').toUpperCase()}'
                  : (layer != null ? 'WORKING, WITH ISSUES: ${layer!.toUpperCase()}' : 'HEALTHY'),
              style: TextStyle(color: failed ? amber : teal, fontSize: 12, fontWeight: FontWeight.w600)),
          const SizedBox(height: 6),
          Text(p.headline, style: const TextStyle(fontSize: 24, fontWeight: FontWeight.w600)),
          if (p.cdn != null || p.server != null)
            Text([if (p.cdn != null) p.cdn!, if (p.server != null) p.server!].join(' · '),
                style: const TextStyle(fontFamily: 'monospace', color: muted)),
        ]),
      ),
      const SizedBox(height: 8),
      _row(_check('DNS', p.dnsError != null ? 'Fail' : '${p.dnsMs ?? '-'}ms', bad: p.dnsError != null),
          _check('Connect', p.tcpMs != null ? '${p.tcpMs}ms' : 'Fail', bad: p.tcpMs == null && p.dnsError == null)),
      _row(_check('TLS', p.tlsError != null ? 'Fail' : (p.tlsDays != null ? '${p.tlsDays}d left' : 'n/a'), bad: p.tlsError != null),
          _check('HTTP', p.status != null ? '${p.status}' : 'Fail', bad: httpBad)),
      _row(_check('First byte', p.ttfbMs != null ? '${p.ttfbMs}ms' : '-'),
          _check('Total', p.totalMs != null ? '${p.totalMs}ms' : '-')),
      if (p.ipMs.isNotEmpty) ...[
        _label('SERVERS BEHIND THIS NAME'),
        for (final e in p.ipMs.entries)
          Text('${e.key}   ${e.value != null ? 'ok ${e.value}ms' : (p.ipErr[e.key] ?? 'failed')}',
              style: TextStyle(fontFamily: 'monospace', fontSize: 12, color: e.value != null ? muted : amber)),
      ],
      if (p.companions.isNotEmpty) ...[
        _label('OTHER PATHS ON THE SAME HOST'),
        Text(p.companions.entries.map((e) => '${e.key} ${e.value ?? 'fail'}').join('   '),
            style: const TextStyle(fontFamily: 'monospace', fontSize: 12, color: muted)),
      ],
      _label('FINDINGS'),
      for (final f in findings)
        Container(
          width: double.infinity,
          margin: const EdgeInsets.only(bottom: 8),
          padding: const EdgeInsets.all(12),
          decoration: BoxDecoration(color: card, borderRadius: BorderRadius.circular(12)),
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Text('${['INFO', 'WARNING', 'PROBLEM'][f.severity]}: ${f.title}',
                style: TextStyle(
                    fontWeight: FontWeight.w600,
                    color: f.severity == 2 ? amber : (f.severity == 1 ? blue : null))),
            if (f.detail.isNotEmpty) Text(f.detail, style: const TextStyle(color: muted, fontSize: 13)),
          ]),
        ),
      const SizedBox(height: 8),
      Row(children: [
        Expanded(
          child: SizedBox(
            height: 48,
            child: OutlinedButton(
              onPressed: () => Navigator.push(
                  context, MaterialPageRoute(builder: (_) => PageCheckScreen(url: p.url.toString()))),
              child: const Text('Page JS check'),
            ),
          ),
        ),
        const SizedBox(width: 8),
        Expanded(
          child: SizedBox(
            height: 48,
            child: OutlinedButton(
              onPressed: () {
                Clipboard.setData(ClipboardData(text: buildReport(p, findings, layer)));
                ScaffoldMessenger.of(context)
                    .showSnackBar(const SnackBar(content: Text('Report copied')));
              },
              child: const Text('Copy report'),
            ),
          ),
        ),
      ]),
      _label('CORRELATED TIMELINE'),
      for (final e in d.timeline)
        Padding(
          padding: const EdgeInsets.only(bottom: 10),
          child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
            SizedBox(width: 72, child: Text(_t(e.at), style: const TextStyle(fontFamily: 'monospace', color: muted))),
            Expanded(child: Text('${e.source}: ${e.title}')),
          ]),
        ),
      const SizedBox(height: 8),
      InkWell(
        borderRadius: BorderRadius.circular(16),
        onTap: () => Navigator.push(context, MaterialPageRoute(builder: (_) => EvidenceScreen(diagnosis: d))),
        child: Container(
          padding: const EdgeInsets.all(16),
          decoration: BoxDecoration(
              color: const Color(0xFF10261F),
              border: Border.all(color: const Color(0xFF1F6B55)),
              borderRadius: BorderRadius.circular(16)),
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Text('BACKEND ANALYSIS · SCORE ${d.score}/100',
                style: const TextStyle(color: teal, fontSize: 12, fontWeight: FontWeight.w600)),
            const SizedBox(height: 6),
            Text(d.summary, style: const TextStyle(fontSize: 16, height: 1.35)),
            const SizedBox(height: 8),
            const Text('View evidence >', style: TextStyle(color: teal)),
          ]),
        ),
      ),
      const SizedBox(height: 24),
    ];
  }

  @override
  Widget build(BuildContext context) {
    final p = probe, d = diagnosis;
    return Scaffold(
      appBar: AppBar(title: const Text('Triage Agent'), actions: [
        IconButton(
          tooltip: 'Integrations',
          icon: const Icon(Icons.settings),
          onPressed: () => Navigator.push(
              context, MaterialPageRoute(builder: (_) => SettingsScreen(settings: settings))),
        ),
      ]),
      body: ListView(padding: const EdgeInsets.all(16), children: [
        TextField(
          controller: url,
          keyboardType: TextInputType.url,
          onSubmitted: (_) => _run(),
          decoration: const InputDecoration(
              labelText: 'Production URL', hintText: 'https://api.acme.com/checkout', border: OutlineInputBorder()),
        ),
        const SizedBox(height: 12),
        Row(children: [
          Expanded(
            child: SizedBox(
              height: 48,
              child: FilledButton(onPressed: busy ? null : _run, child: Text(busy ? 'Inspecting...' : 'Run probe')),
            ),
          ),
          const SizedBox(width: 8),
          SizedBox(height: 48, child: OutlinedButton(onPressed: _demo, child: const Text('Demo'))),
        ]),
        const SizedBox(height: 16),
        if (p == null && recent.isNotEmpty) ...[
          _label('RECENT'),
          for (final e in recent)
            ListTile(
              contentPadding: EdgeInsets.zero,
              title: Text(e.split('\t').first, style: const TextStyle(fontFamily: 'monospace', fontSize: 13)),
              subtitle: Text(e.split('\t').last, style: const TextStyle(color: muted)),
              onTap: () => setState(() => url.text = e.split('\t').first),
            ),
        ],
        if (p != null && d != null) ..._results(p, d),
      ]),
    );
  }
}
