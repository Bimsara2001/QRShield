import 'package:flutter/material.dart';

import '../theme/app_colors.dart';
import '../theme/app_spacing.dart';

/// A visual-only square frame for QR camera content.
///
/// The camera implementation remains entirely owned by the caller through
/// [child]. Decorative layers ignore pointer events so they do not interfere
/// with camera controls or scan detection.
class ScannerFrame extends StatelessWidget {
  final Widget child;
  final double? size;
  final EdgeInsetsGeometry? margin;
  final BorderRadius? borderRadius;

  const ScannerFrame({
    super.key,
    required this.child,
    this.size,
    this.margin,
    this.borderRadius,
  });

  @override
  Widget build(BuildContext context) {
    final palette = context.qrPalette;
    final BorderRadius resolvedRadius =
        borderRadius ?? BorderRadius.circular(AppSpacing.radiusXLarge);

    final frame = Container(
      margin: margin,
      padding: const EdgeInsets.all(AppSpacing.xs),
      decoration: BoxDecoration(
        color: palette.surface,
        borderRadius: resolvedRadius,
        border: Border.all(
          color: AppColors.primaryBlue.withValues(alpha: 0.26),
        ),
        boxShadow: [
          BoxShadow(
            color: AppColors.primaryBlue.withValues(alpha: 0.15),
            blurRadius: 26,
            spreadRadius: -10,
            offset: const Offset(0, 12),
          ),
        ],
      ),
      child: ClipRRect(
        borderRadius: BorderRadius.circular(AppSpacing.radiusLarge),
        child: Stack(
          fit: StackFit.expand,
          children: [
            child,
            IgnorePointer(
              child: _ScannerOverlay(borderRadius: resolvedRadius),
            ),
          ],
        ),
      ),
    );

    if (size != null) {
      return SizedBox.square(dimension: size, child: frame);
    }

    return AspectRatio(aspectRatio: 1, child: frame);
  }
}

class _ScannerOverlay extends StatelessWidget {
  final BorderRadius borderRadius;

  const _ScannerOverlay({required this.borderRadius});

  @override
  Widget build(BuildContext context) {
    final palette = context.qrPalette;
    return Stack(
      fit: StackFit.expand,
      children: [
        DecoratedBox(
          decoration: BoxDecoration(
            borderRadius: borderRadius,
            border: Border.all(
              color: AppColors.primaryBlue.withValues(alpha: 0.20),
            ),
            gradient: LinearGradient(
              begin: Alignment.topCenter,
              end: Alignment.bottomCenter,
              colors: [
                palette.background.withValues(alpha: 0.16),
                Colors.transparent,
                palette.background.withValues(alpha: 0.22),
              ],
            ),
          ),
        ),
        Positioned(
          top: AppSpacing.lg,
          left: AppSpacing.lg,
          child: _ScannerCorner(top: true, left: true),
        ),
        Positioned(
          top: AppSpacing.lg,
          right: AppSpacing.lg,
          child: _ScannerCorner(top: true, right: true),
        ),
        Positioned(
          bottom: AppSpacing.lg,
          left: AppSpacing.lg,
          child: _ScannerCorner(bottom: true, left: true),
        ),
        Positioned(
          bottom: AppSpacing.lg,
          right: AppSpacing.lg,
          child: _ScannerCorner(bottom: true, right: true),
        ),
        const Positioned(
          left: AppSpacing.xxl,
          right: AppSpacing.xxl,
          top: 0,
          bottom: 0,
          child: Align(
            alignment: Alignment.center,
            child: _ScanningLine(),
          ),
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
    const side = BorderSide(color: AppColors.primaryBlueBright, width: 2.5);

    return Container(
      width: 32,
      height: 32,
      decoration: BoxDecoration(
        border: Border(
          top: top ? side : BorderSide.none,
          right: right ? side : BorderSide.none,
          bottom: bottom ? side : BorderSide.none,
          left: left ? side : BorderSide.none,
        ),
        borderRadius: BorderRadius.only(
          topLeft: top && left ? const Radius.circular(AppSpacing.radiusSmall) : Radius.zero,
          topRight: top && right ? const Radius.circular(AppSpacing.radiusSmall) : Radius.zero,
          bottomRight:
              bottom && right ? const Radius.circular(AppSpacing.radiusSmall) : Radius.zero,
          bottomLeft:
              bottom && left ? const Radius.circular(AppSpacing.radiusSmall) : Radius.zero,
        ),
        boxShadow: [
          BoxShadow(
            color: palette.blueGlow,
            blurRadius: 9,
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
      height: 2,
      decoration: BoxDecoration(
        borderRadius: BorderRadius.circular(99),
        gradient: LinearGradient(
          colors: [
            Colors.transparent,
            AppColors.primaryBlue.withValues(alpha: 0.72),
            AppColors.primaryBlueBright,
            AppColors.primaryBlue.withValues(alpha: 0.72),
            Colors.transparent,
          ],
        ),
        boxShadow: [
          BoxShadow(
            color: AppColors.primaryBlue.withValues(alpha: 0.55),
            blurRadius: 10,
          ),
        ],
      ),
    );
  }
}
