import 'package:flutter/material.dart';
import 'correlator.dart';
import 'main.dart';

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
              Text(label, style: const TextStyle(color: muted, fontSize: 12, letterSpacing: 1)),
              const SizedBox(height: 6),
              Container(
                width: double.infinity,
                padding: const EdgeInsets.all(14),
                decoration: BoxDecoration(color: card, borderRadius: BorderRadius.circular(12)),
                child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                  Text(e.title, style: const TextStyle(fontSize: 15)),
                  if (e.detail.isNotEmpty)
                    Text(e.detail, style: const TextStyle(fontFamily: 'monospace', color: muted, fontSize: 12)),
                  if (e.url != null)
                    SelectableText(e.url!, style: const TextStyle(color: blue, fontSize: 12)),
                ]),
              ),
            ]),
          );

    return Scaffold(
      appBar: AppBar(title: const Text('Evidence')),
      body: ListView(padding: const EdgeInsets.all(16), children: [
        Container(
          padding: const EdgeInsets.all(16),
          margin: const EdgeInsets.only(bottom: 16),
          decoration: BoxDecoration(
              color: const Color(0xFF10261F),
              border: Border.all(color: const Color(0xFF1F6B55)),
              borderRadius: BorderRadius.circular(16)),
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Text('CORRELATION SCORE ${d.score}/100',
                style: const TextStyle(color: teal, fontSize: 12, fontWeight: FontWeight.w600)),
            const SizedBox(height: 6),
            Text(d.summary, style: const TextStyle(fontSize: 16, height: 1.35)),
          ]),
        ),
        block('BACKEND ERROR', d.error),
        block('SUSPECT COMMIT', d.commit),
        if (d.notes.isNotEmpty) ...[
          const Text('NOTES', style: TextStyle(color: muted, fontSize: 12, letterSpacing: 1)),
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
