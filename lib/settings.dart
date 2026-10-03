import 'package:flutter/material.dart';
import 'package:shared_preferences/shared_preferences.dart';

class Settings {
  String sentryToken = '', sentryOrg = '', sentryProject = '', ghRepo = '', ghToken = '';

  bool get hasSentry => sentryToken.isNotEmpty && sentryOrg.isNotEmpty && sentryProject.isNotEmpty;
  bool get hasGithub => ghRepo.isNotEmpty;

  static Future<Settings> load() async {
    final p = await SharedPreferences.getInstance();
    return Settings()
      ..sentryToken = p.getString('sentryToken') ?? ''
      ..sentryOrg = p.getString('sentryOrg') ?? ''
      ..sentryProject = p.getString('sentryProject') ?? ''
      ..ghRepo = p.getString('ghRepo') ?? ''
      ..ghToken = p.getString('ghToken') ?? '';
  }

  Future<void> save() async {
    final p = await SharedPreferences.getInstance();
    await p.setString('sentryToken', sentryToken);
    await p.setString('sentryOrg', sentryOrg);
    await p.setString('sentryProject', sentryProject);
    await p.setString('ghRepo', ghRepo);
    await p.setString('ghToken', ghToken);
  }
}

class SettingsScreen extends StatefulWidget {
  const SettingsScreen({super.key, required this.settings});
  final Settings settings;
  @override
  State<SettingsScreen> createState() => _SettingsScreenState();
}

class _SettingsScreenState extends State<SettingsScreen> {
  late final c = {
    'Sentry auth token (read-only)': TextEditingController(text: widget.settings.sentryToken),
    'Sentry organization slug': TextEditingController(text: widget.settings.sentryOrg),
    'Sentry project slug': TextEditingController(text: widget.settings.sentryProject),
    'GitHub repo (owner/name)': TextEditingController(text: widget.settings.ghRepo),
    'GitHub token (optional, for private repos)': TextEditingController(text: widget.settings.ghToken),
  };

  Future<void> _save() async {
    final v = c.values.map((e) => e.text.trim()).toList();
    widget.settings
      ..sentryToken = v[0]
      ..sentryOrg = v[1]
      ..sentryProject = v[2]
      ..ghRepo = v[3]
      ..ghToken = v[4];
    await widget.settings.save();
    if (mounted) Navigator.pop(context);
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Backend correlation')),
      body: ListView(padding: const EdgeInsets.all(16), children: [
        const Text('Optional. The app works fully without these. Add read-only Sentry or GitHub details only if you want failures linked to backend errors and recent commits.',
            style: TextStyle(color: Color(0xFF9AA7B5))),
        const SizedBox(height: 16),
        for (final e in c.entries)
          Padding(
            padding: const EdgeInsets.only(bottom: 12),
            child: TextField(
              controller: e.value,
              obscureText: e.key.contains('token'),
              decoration: InputDecoration(labelText: e.key, border: const OutlineInputBorder()),
            ),
          ),
        SizedBox(height: 48, child: FilledButton(onPressed: _save, child: const Text('Save'))),
      ]),
    );
  }
}
