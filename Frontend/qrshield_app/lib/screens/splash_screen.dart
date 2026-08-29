import 'package:flutter/material.dart';

import '../theme/app_colors.dart';
import '../theme/app_spacing.dart';

/// A short, presentation-only startup sequence for QRShield.
///
/// The screen owns no application state and performs no security work. Its
/// completion callback lets the root replace it with the existing navigation
/// shell without adding a route to the back stack.
class SplashScreen extends StatefulWidget {
  final VoidCallback onFinished;

  const SplashScreen({
    super.key,
    required this.onFinished,
  });

  @override
  State<SplashScreen> createState() => _SplashScreenState();
}

class _SplashScreenState extends State<SplashScreen>
    with SingleTickerProviderStateMixin {
  static const _standardDuration = Duration(milliseconds: 2050);
  static const _reducedMotionDuration = Duration(milliseconds: 520);

  late final AnimationController _controller;
  late final Animation<double> _ambientOpacity;
  late final Animation<double> _logoOpacity;
  late final Animation<double> _logoScale;
  late final Animation<double> _scannerOpacity;
  late final Animation<double> _scannerScale;
  late final Animation<double> _scanLinePosition;
  late final Animation<double> _brandOpacity;
  late final Animation<Offset> _brandOffset;
  late final Animation<double> _statusOpacity;
  late final Animation<double> _contentOpacity;

  bool _started = false;
  bool _finished = false;

  @override
  void initState() {
    super.initState();
    _controller = AnimationController(
      vsync: this,
      duration: _standardDuration,
    );

    _ambientOpacity = CurvedAnimation(
      parent: _controller,
      curve: const Interval(0.0, 0.13, curve: Curves.easeOut),
    );
    _logoOpacity = CurvedAnimation(
      parent: _controller,
      curve: const Interval(0.07, 0.39, curve: Curves.easeOutCubic),
    );
    _logoScale = Tween<double>(begin: 0.75, end: 1).animate(
      CurvedAnimation(
        parent: _controller,
        curve: const Interval(0.07, 0.39, curve: Curves.easeOutBack),
      ),
    );
    _scannerOpacity = CurvedAnimation(
      parent: _controller,
      curve: const Interval(0.24, 0.54, curve: Curves.easeOutCubic),
    );
    _scannerScale = Tween<double>(begin: 0.84, end: 1).animate(
      CurvedAnimation(
        parent: _controller,
        curve: const Interval(0.24, 0.54, curve: Curves.easeOutCubic),
      ),
    );
    _scanLinePosition = Tween<double>(begin: -0.72, end: 0.72).animate(
      CurvedAnimation(
        parent: _controller,
        curve: const Interval(0.25, 0.63, curve: Curves.easeInOutCubic),
      ),
    );
    _brandOpacity = CurvedAnimation(
      parent: _controller,
      curve: const Interval(0.34, 0.71, curve: Curves.easeOutCubic),
    );
    _brandOffset = Tween<Offset>(
      begin: const Offset(0, 0.16),
      end: Offset.zero,
    ).animate(
      CurvedAnimation(
        parent: _controller,
        curve: const Interval(0.34, 0.71, curve: Curves.easeOutCubic),
      ),
    );
    _statusOpacity = CurvedAnimation(
      parent: _controller,
      curve: const Interval(0.58, 0.86, curve: Curves.easeOut),
    );
    _contentOpacity = Tween<double>(begin: 1, end: 0).animate(
      CurvedAnimation(
        parent: _controller,
        curve: const Interval(0.88, 1, curve: Curves.easeInOut),
      ),
    );
  }

  @override
  void didChangeDependencies() {
    super.didChangeDependencies();

    if (_started) return;
    _started = true;
    _controller.duration = MediaQuery.of(context).disableAnimations
        ? _reducedMotionDuration
        : _standardDuration;
    _controller.forward().whenComplete(_complete);
  }

  void _complete() {
    if (_finished || !mounted) return;
    _finished = true;
    widget.onFinished();
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final palette = context.qrPalette;
    final textTheme = Theme.of(context).textTheme;

    return Scaffold(
      backgroundColor: palette.background,
      body: Stack(
        fit: StackFit.expand,
        children: [
          FadeTransition(
            opacity: _ambientOpacity,
            child: IgnorePointer(
              child: DecoratedBox(
                decoration: BoxDecoration(
                  gradient: RadialGradient(
                    center: const Alignment(0, -0.14),
                    radius: 0.86,
                    colors: [
                      AppColors.primaryBlue.withValues(
                        alpha: palette.isDark ? 0.18 : 0.12,
                      ),
                      palette.background,
                    ],
                  ),
                ),
              ),
            ),
          ),
          SafeArea(
            child: LayoutBuilder(
              builder: (context, constraints) {
                final isWide = constraints.maxWidth >= 600;
                final logoSize = isWide ? 144.0 : 120.0;
                final scannerSize = isWide ? 208.0 : 182.0;

                return Center(
                  child: ConstrainedBox(
                    constraints: const BoxConstraints(maxWidth: 440),
                    child: FadeTransition(
                      opacity: _contentOpacity,
                      child: Padding(
                        padding: const EdgeInsets.symmetric(
                          horizontal: AppSpacing.xxl,
                          vertical: AppSpacing.xxxl,
                        ),
                        child: Column(
                          mainAxisSize: MainAxisSize.min,
                          children: [
                            _buildScannerMark(
                              palette: palette,
                              logoSize: logoSize,
                              scannerSize: scannerSize,
                            ),
                            const SizedBox(height: AppSpacing.xxxl),
                            FadeTransition(
                              opacity: _brandOpacity,
                              child: SlideTransition(
                                position: _brandOffset,
                                child: Column(
                                  children: [
                                    Text(
                                      'QRShield',
                                      textAlign: TextAlign.center,
                                      style: textTheme.displaySmall?.copyWith(
                                        color: palette.textPrimary,
                                        fontSize: isWide ? 32 : 30,
                                        fontWeight: FontWeight.w700,
                                        letterSpacing: -0.6,
                                      ),
                                    ),
                                    const SizedBox(height: AppSpacing.xs),
                                    Text(
                                      'Advanced QR Threat Detection',
                                      textAlign: TextAlign.center,
                                      style: textTheme.bodyMedium?.copyWith(
                                        color: palette.textSecondary,
                                        fontWeight: FontWeight.w500,
                                      ),
                                    ),
                                  ],
                                ),
                              ),
                            ),
                            const SizedBox(height: AppSpacing.xxxl),
                            FadeTransition(
                              opacity: _statusOpacity,
                              child: _StartupStatus(palette: palette),
                            ),
                          ],
                        ),
                      ),
                    ),
                  ),
                );
              },
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildScannerMark({
    required QrShieldPalette palette,
    required double logoSize,
    required double scannerSize,
  }) {
    final logoRadius = BorderRadius.circular(AppSpacing.radiusXLarge);

    return SizedBox(
      width: scannerSize,
      height: scannerSize,
      child: Stack(
        fit: StackFit.expand,
        children: [
          FadeTransition(
            opacity: _scannerOpacity,
            child: ScaleTransition(
              scale: _scannerScale,
              child: const IgnorePointer(
                child: _ScannerCorners(),
              ),
            ),
          ),
          Center(
            child: FadeTransition(
              opacity: _logoOpacity,
              child: ScaleTransition(
                scale: _logoScale,
                child: Container(
                  width: logoSize,
                  height: logoSize,
                  decoration: BoxDecoration(
                    borderRadius: logoRadius,
                    border: Border.all(
                      color: AppColors.primaryBlueBright.withValues(alpha: 0.40),
                    ),
                    boxShadow: [
                      BoxShadow(
                        color: palette.blueGlow,
                        blurRadius: 28,
                        spreadRadius: 2,
                      ),
                    ],
                  ),
                  child: ClipRRect(
                    borderRadius: logoRadius,
                    child: Image.asset(
                      'assets/images/Logo.png',
                      fit: BoxFit.contain,
                      filterQuality: FilterQuality.high,
                      semanticLabel: 'QRShield logo',
                    ),
                  ),
                ),
              ),
            ),
          ),
          FadeTransition(
            opacity: _scannerOpacity,
            child: AnimatedBuilder(
              animation: _scanLinePosition,
              builder: (context, child) {
                return Align(
                  alignment: Alignment(0, _scanLinePosition.value),
                  child: child,
                );
              },
              child: const Padding(
                padding: EdgeInsets.symmetric(horizontal: AppSpacing.xxl),
                child: _ScanningLine(),
              ),
            ),
          ),
        ],
      ),
    );
  }
}

class _ScannerCorners extends StatelessWidget {
  const _ScannerCorners();

  @override
  Widget build(BuildContext context) {
    return const Stack(
      children: [
        Positioned(
          top: AppSpacing.md,
          left: AppSpacing.md,
          child: _ScannerCorner(top: true, left: true),
        ),
        Positioned(
          top: AppSpacing.md,
          right: AppSpacing.md,
          child: _ScannerCorner(top: true, right: true),
        ),
        Positioned(
          bottom: AppSpacing.md,
          left: AppSpacing.md,
          child: _ScannerCorner(bottom: true, left: true),
        ),
        Positioned(
          bottom: AppSpacing.md,
          right: AppSpacing.md,
          child: _ScannerCorner(bottom: true, right: true),
        ),
      ],
    );
  }
}

class _ScannerCorner extends StatelessWidget {
  final bool top;
  final bool right;
  final bool bottom;
  final bool left;

  const _ScannerCorner({
    this.top = false,
    this.right = false,
    this.bottom = false,
    this.left = false,
  });

  @override
  Widget build(BuildContext context) {
    final palette = context.qrPalette;
    const side = BorderSide(color: AppColors.primaryBlueBright, width: 2.4);

    return Container(
      width: 34,
      height: 34,
      decoration: BoxDecoration(
        border: Border(
          top: top ? side : BorderSide.none,
          right: right ? side : BorderSide.none,
          bottom: bottom ? side : BorderSide.none,
          left: left ? side : BorderSide.none,
        ),
        borderRadius: BorderRadius.only(
          topLeft: top && left
              ? const Radius.circular(AppSpacing.radiusSmall)
              : Radius.zero,
          topRight: top && right
              ? const Radius.circular(AppSpacing.radiusSmall)
              : Radius.zero,
          bottomRight: bottom && right
              ? const Radius.circular(AppSpacing.radiusSmall)
              : Radius.zero,
          bottomLeft: bottom && left
              ? const Radius.circular(AppSpacing.radiusSmall)
              : Radius.zero,
        ),
        boxShadow: [
          BoxShadow(
            color: palette.blueGlow,
            blurRadius: 10,
          ),
        ],
      ),
    );
  }
}

class _ScanningLine extends StatelessWidget {
  const _ScanningLine();

  @override
  Widget build(BuildContext context) {
    return Container(
      height: 2.5,
      decoration: BoxDecoration(
        borderRadius: BorderRadius.circular(99),
        gradient: LinearGradient(
          colors: [
            Colors.transparent,
            AppColors.primaryBlue.withValues(alpha: 0.70),
            AppColors.primaryBlueBright,
            AppColors.primaryBlue.withValues(alpha: 0.70),
            Colors.transparent,
          ],
        ),
        boxShadow: [
          BoxShadow(
            color: AppColors.primaryBlue.withValues(alpha: 0.50),
            blurRadius: 10,
          ),
        ],
      ),
    );
  }
}

class _StartupStatus extends StatelessWidget {
  final QrShieldPalette palette;

  const _StartupStatus({required this.palette});

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(
        horizontal: AppSpacing.md,
        vertical: AppSpacing.sm,
      ),
      decoration: BoxDecoration(
        color: palette.primaryBlueSoft,
        borderRadius: BorderRadius.circular(99),
        border: Border.all(
          color: AppColors.primaryBlue.withValues(alpha: 0.22),
        ),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          const SizedBox(
            width: 14,
            height: 14,
            child: CircularProgressIndicator(strokeWidth: 2),
          ),
          const SizedBox(width: AppSpacing.sm),
          Text(
            'Initializing secure analysis...',
            style: Theme.of(context).textTheme.bodySmall?.copyWith(
                  color: palette.textSecondary,
                  fontWeight: FontWeight.w600,
                ),
          ),
        ],
      ),
    );
  }
}
