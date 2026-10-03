import 'package:flutter/material.dart';
import 'correlator.dart';
import 'evidence.dart';
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
  bool busy = false;

  @override
  void initState() {
    super.initState();
    Settings.load().then((s) => setState(() => settings = s));
  }

  Future<void> _run() async {
    if (url.text.trim().isEmpty) return;
    setState(() => busy = true);
    final p = await Prober.run(url.text);
    final d = await Correlator(settings).diagnose(p);
    if (mounted) setState(() { probe = p; diagnosis = d; busy = false; });
  }

  void _demo() {
    final (p, d) = Correlator.demo();
    setState(() { url.text = p.url.toString(); probe = p; diagnosis = d; });
  }

  Widget _check(String label, String value, {bool bad = false}) => Expanded(
        child: Container(
          padding: const EdgeInsets.all(12),
          decoration: BoxDecoration(color: card, borderRadius: BorderRadius.circular(12)),
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Text(label, style: const TextStyle(color: muted, fontSize: 12)),
            const SizedBox(height: 2),
            Text(value,
                style: TextStyle(fontFamily: 'monospace', fontSize: 14, color: bad ? amber : null)),
          ]),
        ),
      );

  String _t(DateTime? t) => t == null
      ? ''
      : '${t.hour.toString().padLeft(2, '0')}:${t.minute.toString().padLeft(2, '0')}:${t.second.toString().padLeft(2, '0')}';

  @override
  Widget build(BuildContext context) {
    final p = probe, d = diagnosis;
    return Scaffold(
      appBar: AppBar(title: const Text('Triage Agent'), actions: [
        IconButton(
          tooltip: 'Integrations',
          icon: const Icon(Icons.settings),
          onPressed: () => Navigator.push(context,
              MaterialPageRoute(builder: (_) => SettingsScreen(settings: settings))),
        ),
      ]),
      body: ListView(padding: const EdgeInsets.all(16), children: [
        TextField(
          controller: url,
          keyboardType: TextInputType.url,
          onSubmitted: (_) => _run(),
          decoration: const InputDecoration(
              labelText: 'Production URL', hintText: 'https://api.acme.com/checkout',
              border: OutlineInputBorder()),
        ),
        const SizedBox(height: 12),
        Row(children: [
          Expanded(
            child: SizedBox(
              height: 48,
              child: FilledButton(
                  onPressed: busy ? null : _run,
                  child: Text(busy ? 'Probing...' : 'Run probe')),
            ),
          ),
          const SizedBox(width: 8),
          SizedBox(height: 48, child: OutlinedButton(onPressed: _demo, child: const Text('Demo'))),
        ]),
        const SizedBox(height: 16),
        if (p != null && d != null) ...[
          Container(
            padding: const EdgeInsets.all(16),
            decoration: BoxDecoration(
                color: p.failed ? const Color(0xFF2B1D0A) : const Color(0xFF10261F),
                border: Border.all(color: p.failed ? const Color(0xFF7A4E0E) : const Color(0xFF1F6B55)),
                borderRadius: BorderRadius.circular(16)),
            child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
              Text(p.failed ? 'EXTERNAL SYMPTOM' : 'HEALTHY',
                  style: TextStyle(
                      color: p.failed ? amber : teal, fontSize: 12, fontWeight: FontWeight.w600)),
              const SizedBox(height: 6),
              Text(p.headline, style: const TextStyle(fontSize: 24, fontWeight: FontWeight.w600)),
              if (p.ttfbMs != null)
                Text('TTFB ${(p.ttfbMs! / 1000).toStringAsFixed(1)}s${p.cdn != null ? ' · ${p.cdn}' : ''}',
                    style: const TextStyle(fontFamily: 'monospace', color: muted)),
            ]),
          ),
          const SizedBox(height: 8),
          Row(children: [
            _check('DNS', p.dnsError != null ? 'Fail' : 'Pass · ${p.dnsMs ?? '-'}ms', bad: p.dnsError != null),
            const SizedBox(width: 8),
            _check('TLS', p.tlsError != null ? 'Fail' : p.tlsDays != null ? 'Pass · ${p.tlsDays}d left' : 'n/a',
                bad: p.tlsError != null),
          ]),
          const SizedBox(height: 8),
          Row(children: [
            _check('HTTP', p.status != null ? '${p.status}' : 'Fail', bad: p.failed && p.dnsError == null && p.tlsError == null),
            const SizedBox(width: 8),
            _check('Total', p.totalMs != null ? '${p.totalMs}ms' : '-'),
          ]),
          const SizedBox(height: 16),
          const Text('CORRELATED TIMELINE', style: TextStyle(color: muted, fontSize: 12, letterSpacing: 1)),
          const SizedBox(height: 8),
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
            onTap: () => Navigator.push(
                context, MaterialPageRoute(builder: (_) => EvidenceScreen(diagnosis: d))),
            child: Container(
              padding: const EdgeInsets.all(16),
              decoration: BoxDecoration(
                  color: const Color(0xFF10261F),
                  border: Border.all(color: const Color(0xFF1F6B55)),
                  borderRadius: BorderRadius.circular(16)),
              child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                Text('ANALYSIS · SCORE ${d.score}/100',
                    style: const TextStyle(color: teal, fontSize: 12, fontWeight: FontWeight.w600)),
                const SizedBox(height: 6),
                Text(d.summary, style: const TextStyle(fontSize: 16, height: 1.35)),
                const SizedBox(height: 8),
                const Text('View evidence >', style: TextStyle(color: teal)),
              ]),
            ),
          ),
        ],
      ]),
    );
  }
}
