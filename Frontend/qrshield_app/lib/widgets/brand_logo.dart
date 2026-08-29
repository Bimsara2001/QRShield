import 'package:flutter/material.dart';

import '../theme/app_colors.dart';

/// Shared QRShield branding asset for branded headers and information cards.
class BrandLogo extends StatelessWidget {
  static const String assetPath = 'assets/images/Logo.png';

  final double size;
  final double borderRadius;

  const BrandLogo({
    super.key,
    this.size = 48,
    this.borderRadius = 14,
  });

  @override
  Widget build(BuildContext context) {
    final palette = context.qrPalette;
    final radius = BorderRadius.circular(borderRadius);

    return Container(
      width: size,
      height: size,
      decoration: BoxDecoration(
        borderRadius: radius,
        border: Border.all(
          color: AppColors.primaryBlueBright.withValues(alpha: 0.48),
        ),
        boxShadow: [
          BoxShadow(
            color: palette.blueGlow,
            blurRadius: 18,
            offset: Offset(0, 7),
          ),
        ],
      ),
      child: ClipRRect(
        borderRadius: radius,
        child: Image.asset(
          assetPath,
          fit: BoxFit.cover,
          filterQuality: FilterQuality.high,
          semanticLabel: 'QRShield logo',
        ),
      ),
    );
  }
}
