import 'package:flutter/material.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'correlator.dart';
import 'inspector.dart';
import 'probe.dart';
import 'result_view.dart';
import 'settings.dart';

const bg = Color(0xFF0D1117);
const card = Color(0xFF151B23);
const line = Color(0xFF262E39);
const muted = Color(0xFF93A1B0);
const amber = Color(0xFFF2B04A);
const teal = Color(0xFF4FD6B0);
const blue = Color(0xFF7FB5FF);
const red = Color(0xFFFF7B72);

void main() => runApp(const TriageApp());

class TriageApp extends StatelessWidget {
  const TriageApp({super.key});
  @override
  Widget build(BuildContext context) => MaterialApp(
        title: 'Triage',
        debugShowCheckedModeBanner: false,
        theme: ThemeData.dark(useMaterial3: true).copyWith(
          scaffoldBackgroundColor: bg,
          colorScheme: const ColorScheme.dark(primary: teal, surface: bg),
          appBarTheme: const AppBarTheme(backgroundColor: bg, elevation: 0, scrolledUnderElevation: 0),
          dividerColor: line,
          snackBarTheme: const SnackBarThemeData(behavior: SnackBarBehavior.floating),
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
  Report? report;
  String? stage;
  String? error;
  bool busy = false;
  List<String> recent = [];

  @override
  void initState() {
    super.initState();
    Settings.load().then((s) {
      if (mounted) setState(() => settings = s);
    });
    SharedPreferences.getInstance().then((p) {
      if (mounted) setState(() => recent = p.getStringList('recent') ?? []);
    });
  }

  @override
  void dispose() {
    url.dispose();
    super.dispose();
  }

  Future<void> _run([String? override]) async {
    if (override != null) url.text = override;
    final input = url.text.trim();
    if (input.isEmpty || busy) return;
    FocusScope.of(context).unfocus();
    setState(() {
      busy = true;
      error = null;
      stage = 'Starting';
    });
    try {
      final p = await Prober.run(input, onStage: (s) {
        if (mounted) setState(() => stage = s);
      });
      final f = inspect(p);
      Diagnosis? d;
      if ((settings.hasSentry || settings.hasGithub) && p.failed) {
        try {
          d = await Correlator(settings).diagnose(p);
        } catch (_) {}
      }
      final prefs = await SharedPreferences.getInstance();
      final key = p.url.toString();
      final list = ['$key\t${p.headline}', ...recent.where((e) => e.split('\t').first != key)].take(8).toList();
      await prefs.setStringList('recent', list);
      if (mounted) setState(() { report = Report(p, f, verdict(f), d); recent = list; });
    } catch (e) {
      if (mounted) setState(() => error = 'The check could not finish. Please try again.');
    } finally {
      if (mounted) setState(() { busy = false; stage = null; });
    }
  }

  void _demo() {
    final (p, d) = Correlator.demo();
    final f = inspect(p);
    setState(() {
      url.text = p.url.toString();
      report = Report(p, f, verdict(f), d);
      error = null;
    });
  }

  void _settings() => Navigator.push(
      context, MaterialPageRoute(builder: (_) => SettingsScreen(settings: settings)));

  Widget _empty() => ListView(padding: const EdgeInsets.all(24), children: [
        const SizedBox(height: 24),
        const Icon(Icons.travel_explore_rounded, size: 56, color: teal),
        const SizedBox(height: 16),
        const Text('Find out why a site is failing',
            textAlign: TextAlign.center, style: TextStyle(fontSize: 22, fontWeight: FontWeight.w700)),
        const SizedBox(height: 8),
        const Text(
            'Checks DNS, every server behind the name, the certificate, the response, health endpoints and page files. No account needed.',
            textAlign: TextAlign.center,
            style: TextStyle(color: muted, height: 1.4)),
        const SizedBox(height: 16),
        Center(child: OutlinedButton(onPressed: _demo, child: const Text('See an example'))),
        if (recent.isNotEmpty) ...[
          const SizedBox(height: 24),
          const Text('RECENT', style: TextStyle(color: muted, fontSize: 12, letterSpacing: 1, fontWeight: FontWeight.w600)),
          const SizedBox(height: 4),
          for (final e in recent)
            ListTile(
              contentPadding: EdgeInsets.zero,
              leading: const Icon(Icons.history_rounded, color: muted),
              title: Text(e.split('\t').first, maxLines: 1, overflow: TextOverflow.ellipsis),
              subtitle: Text(e.split('\t').last, style: const TextStyle(color: muted)),
              onTap: () => _run(e.split('\t').first),
            ),
        ],
      ]);

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        titleSpacing: 16,
        title: const Row(children: [
          Icon(Icons.radar_rounded, color: teal),
          SizedBox(width: 8),
          Text('Triage', style: TextStyle(fontWeight: FontWeight.w700)),
        ]),
        actions: [
          IconButton(
              tooltip: 'Optional backend settings', icon: const Icon(Icons.tune_rounded), onPressed: _settings),
        ],
      ),
      body: SafeArea(
        child: Column(children: [
          Padding(
            padding: const EdgeInsets.fromLTRB(16, 4, 16, 8),
            child: Row(children: [
              Expanded(
                child: TextField(
                  controller: url,
                  keyboardType: TextInputType.url,
                  textInputAction: TextInputAction.go,
                  autocorrect: false,
                  enableSuggestions: false,
                  onSubmitted: (_) => _run(),
                  decoration: InputDecoration(
                    hintText: 'api.example.com/checkout',
                    prefixIcon: const Icon(Icons.link_rounded),
                    filled: true,
                    fillColor: card,
                    contentPadding: const EdgeInsets.symmetric(vertical: 16),
                    border: OutlineInputBorder(borderRadius: BorderRadius.circular(14), borderSide: const BorderSide(color: line)),
                    enabledBorder: OutlineInputBorder(borderRadius: BorderRadius.circular(14), borderSide: const BorderSide(color: line)),
                    focusedBorder: OutlineInputBorder(borderRadius: BorderRadius.circular(14), borderSide: const BorderSide(color: teal)),
                  ),
                ),
              ),
              const SizedBox(width: 8),
              SizedBox(
                height: 54,
                child: FilledButton(
                  style: FilledButton.styleFrom(
                      backgroundColor: teal,
                      foregroundColor: const Color(0xFF06231B),
                      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(14))),
                  onPressed: busy ? null : _run,
                  child: Text(report == null ? 'Check' : 'Re-check', style: const TextStyle(fontWeight: FontWeight.w700)),
                ),
              ),
            ]),
          ),
          if (busy) ...[
            const LinearProgressIndicator(minHeight: 2, color: teal, backgroundColor: line),
            Padding(
              padding: const EdgeInsets.symmetric(vertical: 8),
              child: Text('${stage ?? 'Working'}...', style: const TextStyle(color: muted, fontSize: 13)),
            ),
          ],
          if (error != null)
            Padding(
              padding: const EdgeInsets.all(16),
              child: Text(error!, style: const TextStyle(color: red)),
            ),
          Expanded(
            child: report == null
                ? _empty()
                : ResultView(report: report!, onOpenSettings: _settings),
          ),
        ]),
      ),
    );
  }
}
