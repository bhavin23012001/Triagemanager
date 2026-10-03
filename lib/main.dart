import 'package:flutter/material.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'correlator.dart';
import 'inspector.dart';
import 'probe.dart';
import 'result_view.dart';
import 'settings.dart';
import 'ui.dart';

const bg = Color(0xFF04060C);
const card = Color(0xFF0A1020);
const line = Color(0xFF1B2A44);
const muted = Color(0xFF7E92B2);
const amber = Color(0xFFFFB020);
const teal = Color(0xFF00E5FF);
const blue = Color(0xFF6EA8FF);
const red = Color(0xFFFF3D71);
const violet = Color(0xFF9B6BFF);

void main() => runApp(const TriageApp());

class TriageApp extends StatelessWidget {
  const TriageApp({super.key});
  @override
  Widget build(BuildContext context) => MaterialApp(
        title: 'Triage Manager',
        debugShowCheckedModeBanner: false,
        theme: _theme(),
        home: const HomeScreen(),
      );
}

ThemeData _theme() {
  final base = ThemeData.dark(useMaterial3: true);
  final text = base.textTheme.apply(fontFamily: 'Chakra', bodyColor: const Color(0xFFE6F1FF), displayColor: const Color(0xFFE6F1FF));
  final cut = BeveledRectangleBorder(
      borderRadius: const BorderRadius.only(topLeft: Radius.circular(10), bottomRight: Radius.circular(10)),
      side: BorderSide(color: teal.withValues(alpha: 0.7)));
  return base.copyWith(
    scaffoldBackgroundColor: bg,
    textTheme: text,
    primaryTextTheme: text,
    colorScheme: const ColorScheme.dark(primary: teal, secondary: violet, surface: bg, error: red),
    appBarTheme: AppBarTheme(
      backgroundColor: bg,
      elevation: 0,
      scrolledUnderElevation: 0,
      centerTitle: false,
      titleTextStyle: const TextStyle(fontFamily: 'Chakra', fontSize: 20, fontWeight: FontWeight.w700, color: Color(0xFFE6F1FF)),
    ),
    dividerColor: line,
    filledButtonTheme: FilledButtonThemeData(
      style: FilledButton.styleFrom(
        backgroundColor: teal,
        foregroundColor: const Color(0xFF00161B),
        shape: cut,
        textStyle: const TextStyle(fontFamily: 'Chakra', fontWeight: FontWeight.w700, fontSize: 15),
      ),
    ),
    outlinedButtonTheme: OutlinedButtonThemeData(
      style: OutlinedButton.styleFrom(
        foregroundColor: teal,
        shape: cut,
        side: BorderSide.none,
        textStyle: const TextStyle(fontFamily: 'Chakra', fontWeight: FontWeight.w600, fontSize: 14),
      ),
    ),
    textButtonTheme: TextButtonThemeData(style: TextButton.styleFrom(foregroundColor: teal)),
    snackBarTheme: SnackBarThemeData(
      behavior: SnackBarBehavior.floating,
      backgroundColor: card,
      contentTextStyle: const TextStyle(fontFamily: 'Chakra', color: Color(0xFFE6F1FF)),
      shape: cutShape(color: teal.withValues(alpha: 0.6), cut: 10),
    ),
  );
}

/// Shared text-field decoration so inputs match the cut-corner look.
InputDecoration neonField({String? label, String? hint, Widget? prefix}) {
  OutlineInputBorder b(Color c) => OutlineInputBorder(borderRadius: BorderRadius.circular(4), borderSide: BorderSide(color: c));
  return InputDecoration(
    labelText: label,
    hintText: hint,
    prefixIcon: prefix,
    filled: true,
    fillColor: card,
    labelStyle: const TextStyle(color: muted),
    hintStyle: const TextStyle(color: muted, fontFamily: kMono),
    contentPadding: const EdgeInsets.symmetric(horizontal: 14, vertical: 16),
    border: b(line),
    enabledBorder: b(line),
    focusedBorder: b(teal),
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

  Widget _empty() => ListView(padding: const EdgeInsets.fromLTRB(24, 16, 24, 24), children: [
        Center(child: RadarScanner(active: busy)),
        const SizedBox(height: 20),
        Text(busy ? '${stage ?? 'Working'}' : 'Find out why a site is failing',
            textAlign: TextAlign.center,
            style: const TextStyle(fontSize: 26, fontWeight: FontWeight.w700, height: 1.15)),
        const SizedBox(height: 10),
        const Text(
            'Checks DNS, every server behind the name, the certificate, the response, health endpoints and page files. No account needed.',
            textAlign: TextAlign.center,
            style: TextStyle(color: muted, height: 1.45)),
        const SizedBox(height: 18),
        Center(child: OutlinedButton(onPressed: busy ? null : _demo, child: const Text('See an example'))),
        if (recent.isNotEmpty) ...[
          const SizedBox(height: 28),
          Row(children: [
            Container(width: 3, height: 14, color: teal),
            const SizedBox(width: 8),
            const Text('Recent checks', style: TextStyle(color: muted, fontSize: 14, fontWeight: FontWeight.w600)),
          ]),
          const SizedBox(height: 8),
          for (final e in recent)
            Padding(
              padding: const EdgeInsets.only(bottom: 8),
              child: InkWell(
                customBorder: cutShape(cut: 10),
                onTap: () => _run(e.split('\t').first),
                child: NeonPanel(
                  cut: 10,
                  padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 12),
                  child: Row(children: [
                    const Icon(Icons.history_rounded, color: muted, size: 20),
                    const SizedBox(width: 12),
                    Expanded(
                      child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                        Text(e.split('\t').first,
                            maxLines: 1, overflow: TextOverflow.ellipsis, style: const TextStyle(fontFamily: kMono, fontSize: 14)),
                        const SizedBox(height: 2),
                        Text(e.split('\t').last, maxLines: 1, overflow: TextOverflow.ellipsis, style: const TextStyle(color: muted, fontSize: 13)),
                      ]),
                    ),
                  ]),
                ),
              ),
            ),
        ],
      ]);

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        titleSpacing: 16,
        title: Row(children: [
          const Icon(Icons.radar_rounded, color: teal),
          const SizedBox(width: 10),
          const Text('Triage', style: TextStyle(fontWeight: FontWeight.w700, letterSpacing: 1.5)),
          const SizedBox(width: 10),
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 2),
            decoration: ShapeDecoration(shape: cutShape(color: teal.withValues(alpha: 0.6), cut: 6)),
            child: const Text('v0.4', style: TextStyle(fontFamily: kMono, fontSize: 12, color: teal)),
          ),
        ]),
        actions: [
          IconButton(
              tooltip: 'Optional backend settings', icon: const Icon(Icons.tune_rounded), onPressed: _settings),
        ],
      ),
      body: GridBackdrop(
        child: SafeArea(
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
                    style: const TextStyle(fontFamily: kMono, fontSize: 15),
                    onSubmitted: (_) => _run(),
                    decoration: neonField(hint: 'api.example.com/checkout', prefix: const Icon(Icons.link_rounded, color: teal)),
                  ),
                ),
                const SizedBox(width: 8),
                SizedBox(
                  height: 54,
                  child: FilledButton(
                    onPressed: busy ? null : _run,
                    child: Text(report == null ? 'Scan' : 'Re-scan'),
                  ),
                ),
              ]),
            ),
            if (busy) ...[
              const LinearProgressIndicator(minHeight: 2, color: teal, backgroundColor: line),
              Padding(
                padding: const EdgeInsets.symmetric(vertical: 8),
                child: Text('${stage ?? 'Working'}...', style: const TextStyle(color: teal, fontFamily: kMono, fontSize: 13)),
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
      ),
    );
  }
}
