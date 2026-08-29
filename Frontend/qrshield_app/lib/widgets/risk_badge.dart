import 'package:flutter/material.dart';

import '../theme/app_colors.dart';
import '../theme/app_spacing.dart';

/// A semantic, compact risk label that can be shared across scan-related UI.
class RiskBadge extends StatelessWidget {
  final String verdict;
  final bool compact;

  const RiskBadge({
    super.key,
    required this.verdict,
    this.compact = false,
  });

  static Color colorForVerdict(String verdict) {
    switch (_riskLevel(verdict)) {
      case _RiskLevel.low:
        return AppColors.safe;
      case _RiskLevel.medium:
        return AppColors.medium;
      case _RiskLevel.high:
        return AppColors.danger;
      case _RiskLevel.unknown:
        return AppColors.primaryBlue;
    }
  }

  static Color backgroundColorForVerdict(String verdict) {
    switch (_riskLevel(verdict)) {
      case _RiskLevel.low:
        return AppColors.safeBackground;
      case _RiskLevel.medium:
        return AppColors.mediumBackground;
      case _RiskLevel.high:
        return AppColors.dangerBackground;
      case _RiskLevel.unknown:
        return AppColors.primaryBlueSoft;
    }
  }

  static _RiskLevel _riskLevel(String verdict) {
    final String normalized = verdict.toLowerCase();
    if (normalized.contains('low') || normalized.contains('safe')) {
      return _RiskLevel.low;
    }
    if (normalized.contains('medium')) {
      return _RiskLevel.medium;
    }
    if (normalized.contains('high') || normalized.contains('danger')) {
      return _RiskLevel.high;
    }
    return _RiskLevel.unknown;
  }

  @override
  Widget build(BuildContext context) {
    final palette = context.qrPalette;
    final level = _riskLevel(verdict);
    final Color foreground = level == _RiskLevel.unknown
        ? palette.textMuted
        : colorForVerdict(verdict);
    final Color background = switch (level) {
      _RiskLevel.low => palette.safeBackground,
      _RiskLevel.medium => palette.mediumBackground,
      _RiskLevel.high => palette.dangerBackground,
      _RiskLevel.unknown => palette.surfaceSoft,
    };
    final TextTheme textTheme = Theme.of(context).textTheme;

    return Container(
      padding: EdgeInsets.symmetric(
        horizontal: compact ? AppSpacing.sm : AppSpacing.md,
        vertical: compact ? AppSpacing.xs : 6,
      ),
      decoration: BoxDecoration(
        color: background,
        borderRadius: BorderRadius.circular(AppSpacing.radiusSmall),
        border: Border.all(color: foreground.withValues(alpha: 0.32)),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Container(
            width: compact ? 6 : 7,
            height: compact ? 6 : 7,
            decoration: BoxDecoration(
              color: foreground,
              shape: BoxShape.circle,
              boxShadow: [
                BoxShadow(
                  color: foreground.withValues(alpha: 0.36),
                  blurRadius: 7,
                ),
              ],
            ),
          ),
          const SizedBox(width: 6),
          Text(
            verdict,
            maxLines: 1,
            overflow: TextOverflow.ellipsis,
            style: textTheme.labelMedium?.copyWith(
              color: foreground,
              fontWeight: FontWeight.w700,
              fontSize: compact ? 11 : 12,
            ),
          ),
        ],
      ),
    );
  }
}

enum _RiskLevel { low, medium, high, unknown }
