import 'package:flutter/material.dart';

import '../services/api_service.dart';

import '../theme/app_colors.dart';
import '../theme/app_spacing.dart';
import 'cyber_card.dart';
import 'risk_badge.dart';

class ActivityTile extends StatelessWidget {
  final String url;
  final String verdict;
  final String? thumbnailUrl;
  final String? secondaryText;

  const ActivityTile({
    super.key,
    required this.url,
    required this.verdict,
    this.thumbnailUrl,
    this.secondaryText,
  });

  @override
  Widget build(BuildContext context) {
    final TextTheme textTheme = Theme.of(context).textTheme;
    final palette = context.qrPalette;
    final Color riskColor = RiskBadge.colorForVerdict(verdict);

    return CyberCard(
      margin: const EdgeInsets.only(bottom: AppSpacing.md),
      padding: const EdgeInsets.all(AppSpacing.md),
      accentColor: riskColor,
      borderRadius: BorderRadius.circular(AppSpacing.radiusMedium),
      child: Row(
        children: [
          _ActivityThumbnail(
            thumbnailUrl: thumbnailUrl,
            accentColor: riskColor,
          ),
          const SizedBox(width: AppSpacing.md),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              mainAxisSize: MainAxisSize.min,
              children: [
                Text(
                  url,
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                  style: textTheme.titleSmall?.copyWith(
                    color: palette.textPrimary,
                    fontWeight: FontWeight.w600,
                  ),
                ),
                const SizedBox(height: AppSpacing.xs),
                Text(
                  secondaryText?.trim().isNotEmpty == true
                      ? secondaryText!
                      : verdict,
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                  style: textTheme.bodySmall?.copyWith(
                    color: palette.textSecondary,
                    fontWeight: FontWeight.w500,
                  ),
                ),
              ],
            ),
          ),
          const SizedBox(width: AppSpacing.sm),
          Flexible(
            fit: FlexFit.loose,
            child: RiskBadge(verdict: verdict, compact: true),
          ),
        ],
      ),
    );
  }
}

class _ActivityThumbnail extends StatelessWidget {
  final String? thumbnailUrl;
  final Color accentColor;

  const _ActivityThumbnail({
    required this.thumbnailUrl,
    required this.accentColor,
  });

  @override
  Widget build(BuildContext context) {
    final String? imageUrl = thumbnailUrl?.trim();
    final BorderRadius radius = BorderRadius.circular(AppSpacing.radiusSmall);

    return SizedBox(
      width: 46,
      height: 46,
      child: ClipRRect(
        borderRadius: radius,
        child: imageUrl == null || imageUrl.isEmpty
            ? _ThumbnailFallback(accentColor: accentColor)
            : Image.network(
                imageUrl,
                headers: ApiService.authorizationHeaders,
                fit: BoxFit.cover,
                errorBuilder: (_, __, ___) =>
                    _ThumbnailFallback(accentColor: accentColor),
              ),
      ),
    );
  }
}

class _ThumbnailFallback extends StatelessWidget {
  final Color accentColor;

  const _ThumbnailFallback({required this.accentColor});

  @override
  Widget build(BuildContext context) {
    return Container(
      color: accentColor.withValues(alpha: 0.13),
      alignment: Alignment.center,
      child: Icon(Icons.language_rounded, color: accentColor, size: 22),
    );
  }
}
