import 'package:flutter/material.dart';
import 'correlator.dart';
import 'main.dart';
import 'ui.dart';

class EvidenceScreen extends StatelessWidget {
  const EvidenceScreen({super.key, required this.diagnosis});
  final Diagnosis diagnosis;

  @override
  Widget build(BuildContext context) {
    final d = diagnosis;
    Widget block(String label, Evidence? e) => e == null
        ? const SizedBox.shrink()
        : Padding(
            padding: const EdgeInsets.only(bottom: 16),
            child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
              Text(sentence(label), style: const TextStyle(color: muted, fontSize: 14, fontWeight: FontWeight.w600)),
              const SizedBox(height: 6),
              NeonPanel(
                padding: const EdgeInsets.all(14),
                cut: 10,
                child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                  Text(e.title, style: const TextStyle(fontSize: 15)),
                  if (e.detail.isNotEmpty)
                    Text(e.detail, style: const TextStyle(fontFamily: kMono, color: muted, fontSize: 13)),
                  if (e.url != null)
                    SelectableText(e.url!, style: const TextStyle(color: blue, fontSize: 12)),
                ]),
              ),
            ]),
          );

    return Scaffold(
      appBar: AppBar(title: const Text('Evidence')),
      body: ListView(padding: const EdgeInsets.all(16), children: [
        Padding(
          padding: const EdgeInsets.only(bottom: 16),
          child: NeonPanel(
            accent: violet,
            glow: true,
            child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
              Text('Correlation score ${d.score}/100', style: const TextStyle(color: violet, fontSize: 16, fontFamily: kMono)),
              const SizedBox(height: 6),
              Text(d.summary, style: const TextStyle(fontSize: 16, height: 1.35)),
            ]),
          ),
        ),
        block('BACKEND ERROR', d.error),
        block('SUSPECT COMMIT', d.commit),
        if (d.notes.isNotEmpty) ...[
          const Text('Notes', style: TextStyle(color: muted, fontSize: 14, fontWeight: FontWeight.w600)),
          const SizedBox(height: 6),
          for (final n in d.notes) Padding(padding: const EdgeInsets.only(bottom: 6), child: Text(n)),
        ],
        const SizedBox(height: 8),
        const Text(
          'The score is a heuristic based on timing overlap, not a proof of cause. Verify before acting.',
          style: TextStyle(color: muted, fontSize: 12),
        ),
      ]),
    );
  }
}
