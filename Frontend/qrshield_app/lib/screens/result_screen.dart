import 'package:flutter/material.dart';

import '../services/api_service.dart';
import '../services/pdf_service.dart';
import '../theme/app_colors.dart';
import '../theme/app_spacing.dart';
import '../widgets/cyber_card.dart';
import '../widgets/risk_badge.dart';
import '../widgets/screen_header.dart';

class ResultScreen extends StatelessWidget {
  final Map<String, dynamic> result;

  const ResultScreen({super.key, required this.result});

  String _resultText(dynamic value, {String fallback = ''}) {
    final text = value?.toString().trim() ?? '';
    return text.isEmpty ? fallback : text;
  }

  double? _scoreValue(dynamic value) {
    final parsed = value is num
        ? value.toDouble()
        : double.tryParse(value?.toString() ?? '');

    if (parsed == null) return null;

    // This only bounds the visual progress indicator. The supplied score is
    // still displayed without modification below.
    return parsed.clamp(0.0, 100.0).toDouble();
  }

  String _recommendationForVerdict(String verdict) {
    switch (verdict) {
      case 'Low Risk':
        return 'No major phishing indicators were detected.';
      case 'Medium Risk':
        return 'Some suspicious indicators were detected. Review the details before continuing.';
      case 'High Risk':
        return 'Multiple phishing indicators were detected. Avoid opening this destination.';
      default:
        return 'Review the analysis details before proceeding.';
    }
  }

  IconData _iconForVerdict(String verdict) {
    switch (verdict) {
      case 'Low Risk':
        return Icons.verified_user_rounded;
      case 'Medium Risk':
        return Icons.shield_outlined;
      case 'High Risk':
        return Icons.gpp_bad_rounded;
      default:
        return Icons.shield_outlined;
    }
  }

  List<_ThreatMetricData> _virusTotalMetrics(Map? virusTotal) {
    if (virusTotal == null) return const [];

    final metrics = <_ThreatMetricData>[];

    void addMetric(String key, String label, Color color, IconData icon) {
      if (virusTotal.containsKey(key) && virusTotal[key] != null) {
        metrics.add(
          _ThreatMetricData(
            label: label,
            value: virusTotal[key].toString(),
            color: color,
            icon: icon,
          ),
        );
      }
    }

    addMetric(
      'malicious',
      'Malicious',
      AppColors.danger,
      Icons.gpp_bad_outlined,
    );
    addMetric(
      'suspicious',
      'Suspicious',
      AppColors.medium,
      Icons.warning_amber_rounded,
    );
    addMetric('harmless', 'Harmless', AppColors.safe, Icons.verified_outlined);
    addMetric(
      'undetected',
      'Undetected',
      AppColors.primaryBlueBright,
      Icons.remove_red_eye_outlined,
    );

    return metrics;
  }

  bool _hasValidAnalysisResult() {
    // History records created by the current backend predate the status field.
    // They are accepted only when all persisted analysis fields are present;
    // an error response can never satisfy this fallback.
    final statusIsValid =
        result['status'] == 'success' ||
        (result['status'] == null &&
            result['original_url'] is String &&
            result['final_url'] is String &&
            result['risk_score'] is num &&
            result['verdict'] is String);

    const requiredFields = [
      'original_url',
      'final_url',
      'title',
      'screenshot',
      'risk_score',
      'verdict',
      'reasons',
      'virustotal',
    ];

    if (!statusIsValid || !requiredFields.every(result.containsKey)) {
      return false;
    }

    return result['original_url'] is String &&
        (result['original_url'] as String).trim().isNotEmpty &&
        result['final_url'] is String &&
        (result['final_url'] as String).trim().isNotEmpty &&
        result['title'] is String &&
        result['screenshot'] is String &&
        (result['screenshot'] as String).trim().isNotEmpty &&
        result['risk_score'] is num &&
        result['verdict'] is String &&
        (result['verdict'] as String).trim().isNotEmpty &&
        result['reasons'] is List &&
        result['virustotal'] is Map;
  }

  @override
  Widget build(BuildContext context) {
    final palette = context.qrPalette;

    if (!_hasValidAnalysisResult()) {
      return _buildUnavailableAnalysis(context);
    }

    final verdict = _resultText(result['verdict'], fallback: 'Unknown');
    final riskScore = _resultText(result['risk_score'], fallback: '-');
    final scoreValue = _scoreValue(result['risk_score']);
    final reasons = List<dynamic>.from(result['reasons'] as List);
    final rawVirusTotal = result['virustotal'];
    final Map? virusTotal = rawVirusTotal is Map ? rawVirusTotal : null;
    final virusTotalMetrics = _virusTotalMetrics(virusTotal);
    final virusTotalStatus = _resultText(virusTotal?['status']);
    final virusTotalVerdict = _resultText(virusTotal?['verdict']);
    final virusTotalMessage = _resultText(virusTotal?['message']);
    final hasVirusTotalData =
        virusTotalStatus.toLowerCase() != 'error' &&
        (virusTotalMetrics.isNotEmpty || virusTotalVerdict.isNotEmpty);
    final riskColor = RiskBadge.colorForVerdict(verdict);

    return Scaffold(
      backgroundColor: palette.background,
      body: SafeArea(
        child: LayoutBuilder(
          builder: (context, constraints) {
            final horizontalPadding = constraints.maxWidth >= 600
                ? AppSpacing.xxl
                : AppSpacing.pageHorizontal;

            return Align(
              alignment: Alignment.topCenter,
              child: ConstrainedBox(
                constraints: const BoxConstraints(
                  maxWidth: AppSpacing.maxContentWidth,
                ),
                child: SingleChildScrollView(
                  padding: EdgeInsets.fromLTRB(
                    horizontalPadding,
                    AppSpacing.lg,
                    horizontalPadding,
                    AppSpacing.xxxl + 28,
                  ),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      ScreenHeader(
                        title: 'QRShield Analysis',
                        subtitle: 'Security analysis result',
                        leading: _buildBackButton(context),
                      ),
                      const SizedBox(height: AppSpacing.xxl),
                      _buildRiskHero(
                        context,
                        verdict: verdict,
                        riskScore: riskScore,
                        scoreValue: scoreValue,
                        riskColor: riskColor,
                      ),
                      const SizedBox(height: AppSpacing.xxl),
                      _buildSectionHeading(
                        context,
                        icon: Icons.desktop_windows_outlined,
                        title: 'Destination Preview',
                        subtitle: 'Isolated sandbox preview',
                      ),
                      const SizedBox(height: AppSpacing.md),
                      _buildDestinationPreview(context),
                      const SizedBox(height: AppSpacing.xxl),
                      _buildSectionHeading(
                        context,
                        icon: Icons.link_rounded,
                        title: 'URL Details',
                        subtitle: 'Analyzed destination information',
                      ),
                      const SizedBox(height: AppSpacing.md),
                      _buildUrlDetails(context),
                      const SizedBox(height: AppSpacing.xxl),
                      _buildSectionHeading(
                        context,
                        icon: Icons.policy_outlined,
                        title: 'Security Findings',
                        subtitle: 'Indicators observed during analysis',
                      ),
                      const SizedBox(height: AppSpacing.md),
                      _buildSecurityFindings(
                        context,
                        reasons: reasons,
                        riskColor: riskColor,
                      ),
                      const SizedBox(height: AppSpacing.xxl),
                      _buildSectionHeading(
                        context,
                        icon: Icons.hub_outlined,
                        title: 'Threat Intelligence',
                        subtitle: 'VirusTotal analysis',
                      ),
                      const SizedBox(height: AppSpacing.md),
                      _buildVirusTotalSection(
                        context,
                        metrics: virusTotalMetrics,
                        verdict: virusTotalVerdict,
                        isAvailable: hasVirusTotalData,
                        unavailableMessage: virusTotalMessage,
                      ),
                      const SizedBox(height: AppSpacing.xxl),
                      _buildIsolationInfo(context),
                      const SizedBox(height: AppSpacing.xxl),
                      _buildActionArea(context),
                    ],
                  ),
                ),
              ),
            );
          },
        ),
      ),
    );
  }

  Widget _buildUnavailableAnalysis(BuildContext context) {
    final palette = context.qrPalette;
    final textTheme = Theme.of(context).textTheme;

    return Scaffold(
      backgroundColor: palette.background,
      body: SafeArea(
        child: Center(
          child: Padding(
            padding: const EdgeInsets.all(AppSpacing.xl),
            child: ConstrainedBox(
              constraints: const BoxConstraints(maxWidth: 380),
              child: CyberCard(
                accentColor: AppColors.danger,
                borderColor: AppColors.danger.withValues(alpha: 0.36),
                padding: const EdgeInsets.all(AppSpacing.xl),
                child: Column(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    const Icon(
                      Icons.error_outline_rounded,
                      color: AppColors.danger,
                      size: 44,
                    ),
                    const SizedBox(height: AppSpacing.md),
                    Text(
                      'Analysis failed',
                      textAlign: TextAlign.center,
                      style: textTheme.titleLarge?.copyWith(
                        color: palette.textPrimary,
                        fontWeight: FontWeight.w700,
                      ),
                    ),
                    const SizedBox(height: AppSpacing.sm),
                    Text(
                      'Unable to complete security analysis. Please try again.',
                      textAlign: TextAlign.center,
                      style: textTheme.bodyMedium?.copyWith(
                        color: palette.textSecondary,
                        height: 1.4,
                      ),
                    ),
                    const SizedBox(height: AppSpacing.lg),
                    OutlinedButton.icon(
                      onPressed: () => Navigator.pop(context),
                      icon: const Icon(Icons.arrow_back_rounded),
                      label: const Text('Back to scan'),
                    ),
                  ],
                ),
              ),
            ),
          ),
        ),
      ),
    );
  }

  Widget _buildBackButton(BuildContext context) {
    final palette = context.qrPalette;

    return SizedBox(
      width: 42,
      height: 42,
      child: DecoratedBox(
        decoration: BoxDecoration(
          color: palette.surfaceElevated,
          borderRadius: BorderRadius.circular(AppSpacing.radiusMedium),
          border: Border.all(color: palette.border),
          boxShadow: [
            BoxShadow(
              color: palette.shadow,
              blurRadius: 12,
              offset: Offset(0, 5),
            ),
          ],
        ),
        child: IconButton(
          tooltip: 'Back',
          padding: EdgeInsets.zero,
          style: IconButton.styleFrom(
            minimumSize: const Size.square(42),
            shape: RoundedRectangleBorder(
              borderRadius: BorderRadius.circular(AppSpacing.radiusMedium),
            ),
          ),
          onPressed: () {
            Navigator.pop(context);
          },
          icon: Icon(
            Icons.arrow_back_rounded,
            color: palette.textPrimary,
            size: 20,
          ),
        ),
      ),
    );
  }

  Widget _buildRiskHero(
    BuildContext context, {
    required String verdict,
    required String riskScore,
    required double? scoreValue,
    required Color riskColor,
  }) {
    final textTheme = Theme.of(context).textTheme;
    final palette = context.qrPalette;

    return CyberCard(
      accentColor: riskColor,
      borderColor: riskColor.withValues(alpha: 0.42),
      padding: const EdgeInsets.all(AppSpacing.xl),
      gradient: LinearGradient(
        begin: Alignment.topLeft,
        end: Alignment.bottomRight,
        colors: [
          palette.surfaceElevated,
          riskColor.withValues(alpha: 0.10),
          palette.surface,
        ],
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Container(
                width: 54,
                height: 54,
                decoration: BoxDecoration(
                  color: riskColor.withValues(alpha: 0.13),
                  borderRadius: BorderRadius.circular(AppSpacing.radiusMedium),
                  border: Border.all(color: riskColor.withValues(alpha: 0.36)),
                  boxShadow: [
                    BoxShadow(
                      color: riskColor.withValues(alpha: 0.16),
                      blurRadius: 18,
                      offset: const Offset(0, 7),
                    ),
                  ],
                ),
                alignment: Alignment.center,
                child: Icon(
                  _iconForVerdict(verdict),
                  color: riskColor,
                  size: 28,
                ),
              ),
              const SizedBox(width: AppSpacing.md),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      'Security verdict',
                      style: textTheme.labelMedium?.copyWith(
                        color: palette.textSecondary,
                        fontWeight: FontWeight.w600,
                      ),
                    ),
                    const SizedBox(height: AppSpacing.xs),
                    Text(
                      verdict,
                      maxLines: 2,
                      overflow: TextOverflow.ellipsis,
                      style: textTheme.headlineSmall?.copyWith(
                        color: palette.textPrimary,
                        fontWeight: FontWeight.w700,
                        letterSpacing: -0.4,
                      ),
                    ),
                    const SizedBox(height: AppSpacing.sm),
                    RiskBadge(verdict: verdict),
                  ],
                ),
              ),
            ],
          ),
          const SizedBox(height: AppSpacing.lg),
          Text(
            _recommendationForVerdict(verdict),
            style: textTheme.bodyMedium?.copyWith(
              color: palette.textSecondary,
              height: 1.45,
            ),
          ),
          const SizedBox(height: AppSpacing.lg),
          Container(
            width: double.infinity,
            padding: const EdgeInsets.all(AppSpacing.md),
            decoration: BoxDecoration(
              color: palette.background.withValues(alpha: 0.36),
              borderRadius: BorderRadius.circular(AppSpacing.radiusMedium),
              border: Border.all(color: riskColor.withValues(alpha: 0.24)),
            ),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  mainAxisAlignment: MainAxisAlignment.spaceBetween,
                  children: [
                    Text(
                      'Risk Score',
                      style: textTheme.labelLarge?.copyWith(
                        color: palette.textPrimary,
                        fontWeight: FontWeight.w700,
                      ),
                    ),
                    Text(
                      scoreValue == null ? riskScore : '$riskScore / 100',
                      style: textTheme.titleLarge?.copyWith(
                        color: riskColor,
                        fontWeight: FontWeight.w700,
                      ),
                    ),
                  ],
                ),
                if (scoreValue != null) ...[
                  const SizedBox(height: AppSpacing.sm),
                  ClipRRect(
                    borderRadius: BorderRadius.circular(99),
                    child: LinearProgressIndicator(
                      value: scoreValue / 100,
                      minHeight: 8,
                      color: riskColor,
                      backgroundColor: palette.surfaceSoft,
                    ),
                  ),
                  const SizedBox(height: AppSpacing.xs),
                  Row(
                    mainAxisAlignment: MainAxisAlignment.spaceBetween,
                    children: [
                      Text(
                        'Safe',
                        style: textTheme.bodySmall?.copyWith(
                          color: palette.textMuted,
                          fontWeight: FontWeight.w600,
                        ),
                      ),
                      Text(
                        'Caution',
                        style: textTheme.bodySmall?.copyWith(
                          color: palette.textMuted,
                          fontWeight: FontWeight.w600,
                        ),
                      ),
                      Text(
                        'Danger',
                        style: textTheme.bodySmall?.copyWith(
                          color: palette.textMuted,
                          fontWeight: FontWeight.w600,
                        ),
                      ),
                    ],
                  ),
                ],
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildSectionHeading(
    BuildContext context, {
    required IconData icon,
    required String title,
    required String subtitle,
  }) {
    final textTheme = Theme.of(context).textTheme;
    final palette = context.qrPalette;

    return Row(
      children: [
        Container(
          width: 34,
          height: 34,
          decoration: BoxDecoration(
            color: palette.primaryBlueSoft,
            borderRadius: BorderRadius.circular(AppSpacing.radiusSmall),
            border: Border.all(
              color: AppColors.primaryBlue.withValues(alpha: 0.22),
            ),
          ),
          alignment: Alignment.center,
          child: Icon(icon, color: AppColors.primaryBlueBright, size: 18),
        ),
        const SizedBox(width: AppSpacing.sm),
        Expanded(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                title,
                style: textTheme.titleMedium?.copyWith(
                  color: palette.textPrimary,
                  fontWeight: FontWeight.w700,
                ),
              ),
              const SizedBox(height: 2),
              Text(
                subtitle,
                style: textTheme.bodySmall?.copyWith(
                  color: palette.textSecondary,
                ),
              ),
            ],
          ),
        ),
      ],
    );
  }

  Widget _buildDestinationPreview(BuildContext context) {
    final textTheme = Theme.of(context).textTheme;
    final palette = context.qrPalette;

    return CyberCard(
      padding: EdgeInsets.zero,
      accentColor: AppColors.primaryBlue,
      borderColor: palette.borderBright,
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Center(
            child: ConstrainedBox(
              constraints: const BoxConstraints(maxWidth: 760),
              child: ClipRRect(
                borderRadius: const BorderRadius.vertical(
                  top: Radius.circular(AppSpacing.radiusLarge),
                ),
                child: AspectRatio(
                  aspectRatio: 16 / 10,
                  child: Image.network(
                    ApiService.backendAssetUrl(result['screenshot'] as String),
                    headers: ApiService.authorizationHeaders,
                    width: double.infinity,
                    fit: BoxFit.contain,
                    loadingBuilder: (context, child, loadingProgress) {
                      if (loadingProgress == null) return child;

                      return Container(
                        color: palette.surfaceSoft,
                        alignment: Alignment.center,
                        child: const SizedBox(
                          width: 28,
                          height: 28,
                          child: CircularProgressIndicator(strokeWidth: 2.5),
                        ),
                      );
                    },
                    errorBuilder: (context, error, stackTrace) {
                      return Container(
                        color: palette.surfaceSoft,
                        alignment: Alignment.center,
                        child: Column(
                          mainAxisSize: MainAxisSize.min,
                          children: [
                            Icon(
                              Icons.image_not_supported_outlined,
                              color: palette.textMuted,
                              size: 46,
                            ),
                            SizedBox(height: AppSpacing.sm),
                            Text(
                              'Preview unavailable',
                              style: TextStyle(color: palette.textSecondary),
                            ),
                          ],
                        ),
                      );
                    },
                  ),
                ),
              ),
            ),
          ),
          Padding(
            padding: const EdgeInsets.all(AppSpacing.md),
            child: Row(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Icon(
                  Icons.shield_outlined,
                  color: AppColors.primaryBlueBright,
                  size: 18,
                ),
                const SizedBox(width: AppSpacing.sm),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        'Isolated sandbox preview',
                        style: textTheme.labelLarge?.copyWith(
                          color: palette.textPrimary,
                          fontWeight: FontWeight.w700,
                        ),
                      ),
                      const SizedBox(height: 2),
                      Text(
                        'Captured before direct navigation',
                        style: textTheme.bodySmall?.copyWith(
                          color: palette.textSecondary,
                        ),
                      ),
                    ],
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildUrlDetails(BuildContext context) {
    return CyberCard(
      accentColor: AppColors.primaryBlue,
      padding: const EdgeInsets.all(AppSpacing.lg),
      child: Column(
        children: [
          _DetailRow(
            icon: Icons.link_rounded,
            label: 'Original URL',
            value: _resultText(result['original_url'], fallback: 'Unknown'),
          ),
          const Divider(height: AppSpacing.xl),
          _DetailRow(
            icon: Icons.alt_route_rounded,
            label: 'Final URL',
            value: _resultText(result['final_url'], fallback: 'Unknown'),
          ),
          const Divider(height: AppSpacing.xl),
          _DetailRow(
            icon: Icons.title_rounded,
            label: 'Page Title',
            value: _resultText(result['title'], fallback: 'Unknown'),
          ),
        ],
      ),
    );
  }

  Widget _buildSecurityFindings(
    BuildContext context, {
    required dynamic reasons,
    required Color riskColor,
  }) {
    final textTheme = Theme.of(context).textTheme;
    final palette = context.qrPalette;

    if (reasons.isEmpty) {
      return CyberCard(
        accentColor: AppColors.safe,
        borderColor: AppColors.safe.withValues(alpha: 0.32),
        padding: const EdgeInsets.all(AppSpacing.lg),
        child: Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Container(
              width: 38,
              height: 38,
              decoration: BoxDecoration(
                color: palette.safeBackground,
                borderRadius: BorderRadius.circular(AppSpacing.radiusSmall),
              ),
              alignment: Alignment.center,
              child: const Icon(
                Icons.check_circle_outline_rounded,
                color: AppColors.safe,
                size: 21,
              ),
            ),
            const SizedBox(width: AppSpacing.md),
            Expanded(
              child: Text(
                'No major threat indicators detected',
                style: textTheme.bodyMedium?.copyWith(
                  color: palette.textPrimary,
                  height: 1.4,
                  fontWeight: FontWeight.w600,
                ),
              ),
            ),
          ],
        ),
      );
    }

    return CyberCard(
      accentColor: riskColor,
      borderColor: riskColor.withValues(alpha: 0.28),
      padding: const EdgeInsets.all(AppSpacing.md),
      child: Column(
        children: reasons.map<Widget>((reason) {
          return _FindingRow(text: reason.toString(), color: riskColor);
        }).toList(),
      ),
    );
  }

  Widget _buildVirusTotalSection(
    BuildContext context, {
    required List<_ThreatMetricData> metrics,
    required String verdict,
    required bool isAvailable,
    required String unavailableMessage,
  }) {
    final textTheme = Theme.of(context).textTheme;
    final palette = context.qrPalette;

    if (!isAvailable) {
      return CyberCard(
        accentColor: palette.textMuted,
        padding: const EdgeInsets.all(AppSpacing.lg),
        child: Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Container(
              width: 38,
              height: 38,
              decoration: BoxDecoration(
                color: palette.surfaceSoft,
                borderRadius: BorderRadius.circular(AppSpacing.radiusSmall),
                border: Border.all(color: palette.border),
              ),
              alignment: Alignment.center,
              child: Icon(
                Icons.cloud_off_outlined,
                color: palette.textMuted,
                size: 20,
              ),
            ),
            const SizedBox(width: AppSpacing.md),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    'Threat intelligence unavailable',
                    style: textTheme.labelLarge?.copyWith(
                      color: palette.textPrimary,
                      fontWeight: FontWeight.w700,
                    ),
                  ),
                  if (unavailableMessage.isNotEmpty) ...[
                    const SizedBox(height: AppSpacing.xs),
                    Text(
                      unavailableMessage,
                      style: textTheme.bodySmall?.copyWith(
                        color: palette.textSecondary,
                        height: 1.4,
                      ),
                    ),
                  ],
                ],
              ),
            ),
          ],
        ),
      );
    }

    return CyberCard(
      accentColor: AppColors.primaryBlue,
      padding: const EdgeInsets.all(AppSpacing.lg),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          if (metrics.isNotEmpty)
            LayoutBuilder(
              builder: (context, constraints) {
                final columns = constraints.maxWidth >= 660 ? 3 : 2;
                final itemWidth =
                    (constraints.maxWidth - AppSpacing.md * (columns - 1)) /
                    columns;

                return Wrap(
                  spacing: AppSpacing.md,
                  runSpacing: AppSpacing.md,
                  children: metrics
                      .map(
                        (metric) => SizedBox(
                          width: itemWidth,
                          child: _ThreatMetricCard(metric: metric),
                        ),
                      )
                      .toList(),
                );
              },
            ),
          if (metrics.isNotEmpty && verdict.isNotEmpty)
            const SizedBox(height: AppSpacing.md),
          if (verdict.isNotEmpty)
            Container(
              width: double.infinity,
              padding: const EdgeInsets.symmetric(
                horizontal: AppSpacing.md,
                vertical: AppSpacing.sm,
              ),
              decoration: BoxDecoration(
                color: palette.surfaceSoft,
                borderRadius: BorderRadius.circular(AppSpacing.radiusSmall),
                border: Border.all(color: palette.border),
              ),
              child: Row(
                children: [
                  const Icon(
                    Icons.verified_user_outlined,
                    color: AppColors.primaryBlueBright,
                    size: 18,
                  ),
                  const SizedBox(width: AppSpacing.sm),
                  Expanded(
                    child: Text(
                      'VirusTotal verdict',
                      style: textTheme.bodySmall?.copyWith(
                        color: palette.textSecondary,
                        fontWeight: FontWeight.w600,
                      ),
                    ),
                  ),
                  const SizedBox(width: AppSpacing.sm),
                  Flexible(
                    child: Text(
                      verdict,
                      textAlign: TextAlign.end,
                      overflow: TextOverflow.ellipsis,
                      style: textTheme.labelMedium?.copyWith(
                        color: palette.textPrimary,
                        fontWeight: FontWeight.w700,
                      ),
                    ),
                  ),
                ],
              ),
            ),
        ],
      ),
    );
  }

  Widget _buildIsolationInfo(BuildContext context) {
    final textTheme = Theme.of(context).textTheme;
    final palette = context.qrPalette;

    return CyberCard(
      accentColor: AppColors.primaryBlue,
      borderColor: AppColors.primaryBlue.withValues(alpha: 0.28),
      padding: const EdgeInsets.all(AppSpacing.lg),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Container(
            width: 40,
            height: 40,
            decoration: BoxDecoration(
              color: palette.primaryBlueSoft,
              borderRadius: BorderRadius.circular(AppSpacing.radiusSmall),
              border: Border.all(
                color: AppColors.primaryBlue.withValues(alpha: 0.24),
              ),
            ),
            alignment: Alignment.center,
            child: const Icon(
              Icons.shield_outlined,
              color: AppColors.primaryBlueBright,
              size: 21,
            ),
          ),
          const SizedBox(width: AppSpacing.md),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  'Analyzed in isolation',
                  style: textTheme.labelLarge?.copyWith(
                    color: palette.textPrimary,
                    fontWeight: FontWeight.w700,
                  ),
                ),
                const SizedBox(height: AppSpacing.xs),
                Text(
                  'The destination was analyzed before direct navigation from your device.',
                  style: textTheme.bodySmall?.copyWith(
                    color: palette.textSecondary,
                    height: 1.45,
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildActionArea(BuildContext context) {
    final textTheme = Theme.of(context).textTheme;
    final palette = context.qrPalette;

    return CyberCard(
      accentColor: AppColors.primaryBlue,
      padding: const EdgeInsets.all(AppSpacing.md),
      child: Column(
        children: [
          SizedBox(
            width: double.infinity,
            child: OutlinedButton.icon(
              onPressed: () async {
                await PdfService.generateScanReport(result);
              },
              style: OutlinedButton.styleFrom(
                foregroundColor: Theme.of(context).colorScheme.secondary,
                backgroundColor: palette.primaryBlueSoft,
                side: BorderSide(
                  color: AppColors.primaryBlue.withValues(alpha: 0.55),
                ),
                padding: const EdgeInsets.symmetric(
                  vertical: AppSpacing.md,
                  horizontal: AppSpacing.lg,
                ),
                shape: RoundedRectangleBorder(
                  borderRadius: BorderRadius.circular(AppSpacing.radiusMedium),
                ),
                textStyle: textTheme.labelLarge?.copyWith(
                  fontWeight: FontWeight.w700,
                ),
              ),
              icon: const Icon(Icons.file_download_outlined, size: 20),
              label: const Text('Export Security Report'),
            ),
          ),
          const SizedBox(height: AppSpacing.sm),
          SizedBox(
            width: double.infinity,
            child: TextButton.icon(
              onPressed: () {
                Navigator.pop(context);
              },
              style: TextButton.styleFrom(
                foregroundColor: palette.textSecondary,
                padding: const EdgeInsets.symmetric(
                  vertical: AppSpacing.md,
                  horizontal: AppSpacing.lg,
                ),
              ),
              icon: const Icon(Icons.arrow_back_rounded, size: 19),
              label: const Text('Back'),
            ),
          ),
        ],
      ),
    );
  }
}

class _DetailRow extends StatelessWidget {
  final IconData icon;
  final String label;
  final String value;

  const _DetailRow({
    required this.icon,
    required this.label,
    required this.value,
  });

  @override
  Widget build(BuildContext context) {
    final textTheme = Theme.of(context).textTheme;
    final palette = context.qrPalette;

    return Row(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Container(
          width: 34,
          height: 34,
          decoration: BoxDecoration(
            color: palette.primaryBlueSoft,
            borderRadius: BorderRadius.circular(AppSpacing.radiusSmall),
          ),
          alignment: Alignment.center,
          child: Icon(icon, color: AppColors.primaryBlueBright, size: 18),
        ),
        const SizedBox(width: AppSpacing.md),
        Expanded(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                label,
                style: textTheme.bodySmall?.copyWith(
                  color: palette.textMuted,
                  fontWeight: FontWeight.w600,
                ),
              ),
              const SizedBox(height: AppSpacing.xs),
              SelectableText(
                value,
                style: textTheme.bodyMedium?.copyWith(
                  color: palette.textPrimary,
                  height: 1.42,
                  fontWeight: FontWeight.w500,
                ),
              ),
            ],
          ),
        ),
      ],
    );
  }
}

class _FindingRow extends StatelessWidget {
  final String text;
  final Color color;

  const _FindingRow({required this.text, required this.color});

  @override
  Widget build(BuildContext context) {
    final textTheme = Theme.of(context).textTheme;
    final palette = context.qrPalette;

    return Container(
      width: double.infinity,
      margin: const EdgeInsets.only(bottom: AppSpacing.sm),
      padding: const EdgeInsets.all(AppSpacing.md),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.07),
        borderRadius: BorderRadius.circular(AppSpacing.radiusMedium),
        border: Border.all(color: color.withValues(alpha: 0.20)),
      ),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Icon(Icons.warning_amber_rounded, color: color, size: 20),
          const SizedBox(width: AppSpacing.sm),
          Expanded(
            child: Text(
              text,
              style: textTheme.bodyMedium?.copyWith(
                color: palette.textPrimary,
                height: 1.42,
              ),
            ),
          ),
        ],
      ),
    );
  }
}

class _ThreatMetricData {
  final String label;
  final String value;
  final Color color;
  final IconData icon;

  const _ThreatMetricData({
    required this.label,
    required this.value,
    required this.color,
    required this.icon,
  });
}

class _ThreatMetricCard extends StatelessWidget {
  final _ThreatMetricData metric;

  const _ThreatMetricCard({required this.metric});

  @override
  Widget build(BuildContext context) {
    final textTheme = Theme.of(context).textTheme;
    final palette = context.qrPalette;

    return Container(
      padding: const EdgeInsets.all(AppSpacing.md),
      decoration: BoxDecoration(
        color: metric.color.withValues(alpha: 0.08),
        borderRadius: BorderRadius.circular(AppSpacing.radiusMedium),
        border: Border.all(color: metric.color.withValues(alpha: 0.24)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Icon(metric.icon, color: metric.color, size: 19),
          const SizedBox(height: AppSpacing.sm),
          Text(
            metric.value,
            maxLines: 1,
            overflow: TextOverflow.ellipsis,
            style: textTheme.titleLarge?.copyWith(
              color: palette.textPrimary,
              fontWeight: FontWeight.w700,
            ),
          ),
          const SizedBox(height: 2),
          Text(
            metric.label,
            maxLines: 1,
            overflow: TextOverflow.ellipsis,
            style: textTheme.bodySmall?.copyWith(
              color: palette.textSecondary,
              fontWeight: FontWeight.w600,
            ),
          ),
        ],
      ),
    );
  }
}
