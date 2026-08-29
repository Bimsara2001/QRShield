import 'package:flutter/material.dart';

import '../theme/app_colors.dart';
import '../theme/app_spacing.dart';

/// A shared elevated surface for QRShield's security interface.
///
/// The optional [accentColor] gently tints the card edge and shadow without
/// overpowering the content. Use [borderColor] when a component needs a
/// semantic border color, such as a risk-specific metric.
class CyberCard extends StatelessWidget {
  final Widget child;
  final EdgeInsetsGeometry? padding;
  final Color? borderColor;
  final Color? accentColor;
  final BorderRadius? borderRadius;
  final Gradient? gradient;
  final EdgeInsetsGeometry? margin;

  const CyberCard({
    super.key,
    required this.child,
    this.padding,
    this.borderColor,
    this.accentColor,
    this.borderRadius,
    this.gradient,
    this.margin,
  });

  @override
  Widget build(BuildContext context) {
    final palette = context.qrPalette;
    final Color resolvedAccent = accentColor ?? AppColors.primaryBlue;
    final BorderRadius resolvedRadius =
        borderRadius ?? BorderRadius.circular(AppSpacing.radiusLarge);

    return Container(
      margin: margin,
      padding: padding ?? const EdgeInsets.all(AppSpacing.lg),
      decoration: BoxDecoration(
        color: gradient == null ? palette.surfaceElevated : null,
        gradient:
            gradient ??
            LinearGradient(
              begin: Alignment.topLeft,
              end: Alignment.bottomRight,
              colors: [
                palette.surfaceElevated,
                palette.surface,
              ],
            ),
        borderRadius: resolvedRadius,
        border: Border.all(
          color: borderColor ?? palette.border,
        ),
        boxShadow: [
          BoxShadow(
            color: resolvedAccent.withValues(alpha: 0.08),
            blurRadius: 22,
            spreadRadius: -8,
            offset: const Offset(0, 10),
          ),
        ],
      ),
      child: child,
    );
  }
}
