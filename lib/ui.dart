import 'dart:math' as math;
import 'package:flutter/material.dart';
import 'main.dart' show card, line, teal;

const double kCut = 14;
const String kMono = 'TechMono';

/// Chamfered corners (top-left and bottom-right) used on every surface.
ShapeBorder cutShape({Color? color, double cut = kCut, double width = 1}) => BeveledRectangleBorder(
      borderRadius: BorderRadius.only(topLeft: Radius.circular(cut), bottomRight: Radius.circular(cut)),
      side: BorderSide(color: color ?? line, width: width),
    );

/// "PRIMARY ISSUE" -> "Primary issue"
String sentence(String t) => t.isEmpty ? t : t[0].toUpperCase() + t.substring(1).toLowerCase();

class NeonPanel extends StatelessWidget {
  const NeonPanel({
    super.key,
    required this.child,
    this.accent,
    this.padding = const EdgeInsets.all(16),
    this.glow = false,
    this.cut = kCut,
  });
  final Widget child;
  final Color? accent;
  final EdgeInsets padding;
  final bool glow;
  final double cut;

  @override
  Widget build(BuildContext context) {
    final a = accent;
    return Container(
      width: double.infinity,
      padding: padding,
      decoration: ShapeDecoration(
        shape: cutShape(color: a == null ? line : a.withValues(alpha: 0.6), cut: cut),
        gradient: LinearGradient(
          begin: Alignment.topLeft,
          end: Alignment.bottomRight,
          colors: [(a ?? teal).withValues(alpha: a == null ? 0.05 : 0.12), card],
        ),
        shadows: glow && a != null ? [BoxShadow(color: a.withValues(alpha: 0.2), blurRadius: 28)] : null,
      ),
      child: child,
    );
  }
}

/// Faint grid with a cyan bloom at the top. Used behind the home screen only.
class GridBackdrop extends StatelessWidget {
  const GridBackdrop({super.key, required this.child});
  final Widget child;
  @override
  Widget build(BuildContext context) => Stack(children: [
        Positioned.fill(child: CustomPaint(painter: _GridPainter())),
        child,
      ]);
}

class _GridPainter extends CustomPainter {
  @override
  void paint(Canvas canvas, Size size) {
    final bloom = Paint()
      ..shader = RadialGradient(
        colors: [teal.withValues(alpha: 0.16), teal.withValues(alpha: 0)],
      ).createShader(Rect.fromCircle(center: Offset(size.width / 2, 120), radius: size.width * 0.9));
    canvas.drawRect(Offset.zero & size, bloom);
    final p = Paint()
      ..color = teal.withValues(alpha: 0.05)
      ..strokeWidth = 1;
    const step = 32.0;
    for (double x = 0; x <= size.width; x += step) {
      canvas.drawLine(Offset(x, 0), Offset(x, size.height), p);
    }
    for (double y = 0; y <= size.height; y += step) {
      canvas.drawLine(Offset(0, y), Offset(size.width, y), p);
    }
  }

  @override
  bool shouldRepaint(covariant CustomPainter old) => false;
}

class RadarScanner extends StatefulWidget {
  const RadarScanner({super.key, this.active = false, this.size = 230, this.color = teal});
  final bool active;
  final double size;
  final Color color;
  @override
  State<RadarScanner> createState() => _RadarScannerState();
}

class _RadarScannerState extends State<RadarScanner> with SingleTickerProviderStateMixin {
  late final AnimationController _c = AnimationController(vsync: this, duration: const Duration(seconds: 5));
  bool _reduce = false;

  @override
  void didChangeDependencies() {
    super.didChangeDependencies();
    _reduce = MediaQuery.of(context).disableAnimations;
    _sync();
  }

  @override
  void didUpdateWidget(covariant RadarScanner old) {
    super.didUpdateWidget(old);
    if (old.active != widget.active) _sync();
  }

  void _sync() {
    if (_reduce) {
      _c.stop();
      return;
    }
    _c.repeat(period: Duration(milliseconds: widget.active ? 1400 : 5200));
  }

  @override
  void dispose() {
    _c.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) => SizedBox(
        width: widget.size,
        height: widget.size,
        child: AnimatedBuilder(
          animation: _c,
          builder: (_, __) => CustomPaint(painter: _RadarPainter(_reduce ? 0.12 : _c.value, widget.color, widget.active)),
        ),
      );
}

class _RadarPainter extends CustomPainter {
  _RadarPainter(this.t, this.color, this.active);
  final double t;
  final Color color;
  final bool active;

  static const _blips = [(0.9, 0.62), (2.4, 0.38), (3.9, 0.8), (5.3, 0.5)];

  @override
  void paint(Canvas canvas, Size size) {
    final c = size.center(Offset.zero);
    final r = size.width / 2 - 2;
    final ring = Paint()
      ..style = PaintingStyle.stroke
      ..strokeWidth = 1
      ..color = color.withValues(alpha: 0.22);
    for (var i = 1; i <= 4; i++) {
      canvas.drawCircle(c, r * i / 4, ring);
    }
    canvas.drawLine(Offset(c.dx - r, c.dy), Offset(c.dx + r, c.dy), ring);
    canvas.drawLine(Offset(c.dx, c.dy - r), Offset(c.dx, c.dy + r), ring);

    final tick = Paint()
      ..strokeWidth = 1
      ..color = color.withValues(alpha: 0.5);
    for (var i = 0; i < 72; i++) {
      final a = i * 2 * math.pi / 72;
      final len = i % 6 == 0 ? 10.0 : 5.0;
      canvas.drawLine(c + Offset.fromDirection(a, r - len), c + Offset.fromDirection(a, r), tick);
    }

    final ang = t * 2 * math.pi;
    final rect = Rect.fromCircle(center: c, radius: r - 1);
    final sweep = Paint()
      ..shader = SweepGradient(
        colors: [color.withValues(alpha: 0), color.withValues(alpha: 0), color.withValues(alpha: active ? 0.7 : 0.5)],
        stops: const [0, 0.72, 1],
        transform: GradientRotation(ang),
      ).createShader(rect);
    canvas.drawCircle(c, r - 1, sweep);
    canvas.drawLine(
        c,
        c + Offset.fromDirection(ang, r - 1),
        Paint()
          ..strokeWidth = 1.5
          ..color = color.withValues(alpha: 0.95));

    for (final b in _blips) {
      var d = (ang - b.$1) % (2 * math.pi);
      if (d < 0) d += 2 * math.pi;
      final a = (1 - d / (2 * math.pi)).clamp(0.0, 1.0).toDouble();
      final pos = c + Offset.fromDirection(b.$1, r * b.$2);
      canvas.drawCircle(pos, 7, Paint()..color = color.withValues(alpha: 0.25 * a));
      canvas.drawCircle(pos, 2.5, Paint()..color = color.withValues(alpha: 0.2 + 0.8 * a));
    }
    canvas.drawCircle(c, 3, Paint()..color = color);
    canvas.drawCircle(c, r, Paint()
      ..style = PaintingStyle.stroke
      ..strokeWidth = 1.5
      ..color = color.withValues(alpha: 0.7));
  }

  @override
  bool shouldRepaint(covariant _RadarPainter old) => old.t != t || old.active != active || old.color != color;
}
