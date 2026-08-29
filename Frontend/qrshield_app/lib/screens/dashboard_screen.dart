import 'package:flutter/material.dart';

import '../services/history_service.dart';
import '../services/stats_service.dart';
import '../theme/app_colors.dart';
import '../theme/app_spacing.dart';
import '../widgets/activity_tile.dart';
import '../widgets/brand_logo.dart';
import '../widgets/cyber_card.dart';
import '../widgets/stat_card.dart';

class DashboardScreen extends StatefulWidget {
  final VoidCallback? onViewAll;

  const DashboardScreen({
    super.key,
    this.onViewAll,
  });

  @override
  State<DashboardScreen> createState() => _DashboardScreenState();
}

class _DashboardScreenState extends State<DashboardScreen> {
  List scans = [];
  Map<String, dynamic> stats = {};

  bool loading = true;

  @override
  void initState() {
    super.initState();
    loadDashboardData();
  }

  Future<void> loadDashboardData() async {
    setState(() {
      loading = true;
    });

    try {
      final historyData = await HistoryService.getHistory();

      final statsData = await StatsService.getStats();

      setState(() {
        scans = historyData;
        stats = statsData;
        loading = false;
      });
    } catch (e) {
      print("Dashboard Error: $e");

      setState(() {
        loading = false;
      });
    }
  }

  int _statValue(String key) {
    final value = stats[key];

    if (value is int) return value;
    if (value is num) return value.toInt();

    return int.tryParse(value?.toString() ?? '') ?? 0;
  }

  String _scanText(dynamic value, {String fallback = ''}) {
    final text = value?.toString().trim() ?? '';
    return text.isEmpty ? fallback : text;
  }

  @override
  Widget build(BuildContext context) {
    final palette = context.qrPalette;

    return Scaffold(
      backgroundColor: palette.background,
      body: Stack(
        children: [
          Positioned.fill(
            child: IgnorePointer(child: _buildAmbientBackground()),
          ),
          SafeArea(
            bottom: false,
            child: LayoutBuilder(
              builder: (context, constraints) {
                final pagePadding = constraints.maxWidth >= 600
                    ? AppSpacing.xxl
                    : AppSpacing.pageHorizontal;

                return Align(
                  alignment: Alignment.topCenter,
                  child: ConstrainedBox(
                    constraints: const BoxConstraints(maxWidth: 920),
                    child: Column(
                      children: [
                        Padding(
                          padding: EdgeInsets.fromLTRB(
                            pagePadding,
                            AppSpacing.xl,
                            pagePadding,
                            AppSpacing.lg,
                          ),
                          child: _buildDashboardHeader(),
                        ),
                        Expanded(
                          child: loading
                              ? _buildLoadingState()
                              : SingleChildScrollView(
                                  padding: EdgeInsets.fromLTRB(
                                    pagePadding,
                                    AppSpacing.xs,
                                    pagePadding,
                                    AppSpacing.xxxl + AppSpacing.lg,
                                  ),
                                  child: _buildDashboardContent(),
                                ),
                        ),
                      ],
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

  Widget _buildAmbientBackground() {
    return ClipRect(
      child: Stack(
        children: [
          Align(
            alignment: Alignment.topCenter,
            child: Transform.translate(
              offset: const Offset(0, -255),
              child: Container(
                width: 620,
                height: 620,
                decoration: BoxDecoration(
                  shape: BoxShape.circle,
                  gradient: RadialGradient(
                    colors: [
                      AppColors.primaryBlue.withValues(alpha: 0.14),
                      AppColors.primaryBlue.withValues(alpha: 0),
                    ],
                  ),
                ),
              ),
            ),
          ),
          Positioned(
            right: -160,
            top: 380,
            child: Container(
              width: 300,
              height: 300,
              decoration: BoxDecoration(
                shape: BoxShape.circle,
                gradient: RadialGradient(
                  colors: [
                    AppColors.primaryBlue.withValues(alpha: 0.045),
                    AppColors.primaryBlue.withValues(alpha: 0),
                  ],
                ),
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildDashboardHeader() {
    final textTheme = Theme.of(context).textTheme;
    final palette = context.qrPalette;

    return Row(
      crossAxisAlignment: CrossAxisAlignment.center,
      children: [
        _buildBrandMark(),
        const SizedBox(width: AppSpacing.lg),
        Expanded(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            mainAxisSize: MainAxisSize.min,
            children: [
              Text(
                'QRShield',
                maxLines: 1,
                overflow: TextOverflow.ellipsis,
                style: textTheme.headlineSmall?.copyWith(
                  color: palette.textPrimary,
                  fontSize: 27,
                  fontWeight: FontWeight.w700,
                  letterSpacing: -0.55,
                ),
              ),
              const SizedBox(height: AppSpacing.xs),
              Text(
                'Advanced QR Threat Detection',
                maxLines: 2,
                overflow: TextOverflow.ellipsis,
                style: textTheme.bodyMedium?.copyWith(
                  color: palette.textSecondary,
                  fontSize: 13,
                  fontWeight: FontWeight.w500,
                  height: 1.35,
                ),
              ),
            ],
          ),
        ),
        const SizedBox(width: AppSpacing.md),
        _buildRefreshButton(),
      ],
    );
  }

  Widget _buildBrandMark() {
    return BrandLogo(
      size: MediaQuery.sizeOf(context).width >= 600 ? 54 : 48,
    );
  }

  Widget _buildRefreshButton() {
    final palette = context.qrPalette;

    return SizedBox(
      width: 48,
      height: 48,
      child: DecoratedBox(
        decoration: BoxDecoration(
          color: palette.surfaceElevated,
          shape: BoxShape.circle,
          border: Border.all(
            color: AppColors.primaryBlue.withValues(alpha: 0.38),
          ),
          boxShadow: [
            BoxShadow(
              color: palette.blueGlow,
              blurRadius: 16,
              offset: Offset(0, 6),
            ),
          ],
        ),
        child: IconButton(
          tooltip: 'Refresh dashboard',
          onPressed: loadDashboardData,
          padding: EdgeInsets.zero,
          style: IconButton.styleFrom(
            foregroundColor: AppColors.primaryBlueBright,
            minimumSize: const Size.square(48),
            shape: const CircleBorder(),
          ),
          icon: const Icon(Icons.refresh_rounded, size: 22),
        ),
      ),
    );
  }

  Widget _buildLoadingState() {
    final palette = context.qrPalette;

    return Center(
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          CircularProgressIndicator(),
          SizedBox(height: AppSpacing.md),
          Text(
            'Loading security dashboard...',
            style: TextStyle(color: palette.textSecondary),
          ),
        ],
      ),
    );
  }

  Widget _buildDashboardContent() {
    final totalScans = _statValue('total_scans');
    final highRisk = _statValue('high_risk');
    final lowRisk = _statValue('low_risk');
    final mediumRisk = _statValue('medium_risk');

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        _buildProtectionStatus(),
        const SizedBox(height: AppSpacing.xxl),
        _buildSectionHeading(
          title: 'Threat Snapshot',
          subtitle: 'Live scan statistics',
        ),
        const SizedBox(height: AppSpacing.md),
        _buildStatisticsGrid(
          totalScans: totalScans,
          highRisk: highRisk,
          lowRisk: lowRisk,
          mediumRisk: mediumRisk,
        ),
        const SizedBox(height: AppSpacing.xxl),
        _buildSecurityOverview(
          totalScans: totalScans,
          lowRisk: lowRisk,
          mediumRisk: mediumRisk,
          highRisk: highRisk,
        ),
        const SizedBox(height: AppSpacing.xxl),
        _buildRecentActivity(),
      ],
    );
  }

  Widget _buildProtectionStatus() {
    final textTheme = Theme.of(context).textTheme;
    final palette = context.qrPalette;

    return CyberCard(
      accentColor: AppColors.safe,
      borderColor: AppColors.safe.withValues(alpha: 0.38),
      borderRadius: BorderRadius.circular(AppSpacing.xl),
      padding: const EdgeInsets.all(AppSpacing.xl),
      gradient: LinearGradient(
        begin: Alignment.topLeft,
        end: Alignment.bottomRight,
        colors: [
          palette.isDark
              ? const Color(0xFF102C20)
              : AppColors.safe.withValues(alpha: 0.11),
          palette.isDark ? const Color(0xFF102117) : palette.surfaceElevated,
          palette.surface,
        ],
      ),
      child: Row(
        children: [
          Container(
            width: 58,
            height: 58,
            decoration: BoxDecoration(
              color: palette.safeBackground,
              borderRadius: BorderRadius.circular(AppSpacing.radiusLarge),
              border: Border.all(
                color: AppColors.safe.withValues(alpha: 0.30),
              ),
              boxShadow: [
                BoxShadow(
                  color: AppColors.safe.withValues(alpha: 0.15),
                  blurRadius: 18,
                  offset: const Offset(0, 7),
                ),
              ],
            ),
            alignment: Alignment.center,
            child: const Icon(
              Icons.verified_user_rounded,
              color: AppColors.safe,
              size: 30,
            ),
          ),
          const SizedBox(width: AppSpacing.lg),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              mainAxisSize: MainAxisSize.min,
              children: [
                Text(
                  'Your protection is active',
                  style: textTheme.titleMedium?.copyWith(
                    color: palette.textPrimary,
                    fontSize: 18,
                    fontWeight: FontWeight.w700,
                    letterSpacing: -0.2,
                  ),
                ),
                const SizedBox(height: AppSpacing.xs),
                Text(
                  'QRShield is monitoring scanned links for threats',
                  maxLines: 2,
                  overflow: TextOverflow.ellipsis,
                  style: textTheme.bodySmall?.copyWith(
                    color: palette.textSecondary,
                    fontSize: 12,
                    height: 1.42,
                  ),
                ),
              ],
            ),
          ),
          const SizedBox(width: AppSpacing.sm),
          _buildActivePill(),
        ],
      ),
    );
  }

  Widget _buildActivePill() {
    final palette = context.qrPalette;

    return Container(
      padding: const EdgeInsets.symmetric(
        horizontal: AppSpacing.md,
        vertical: AppSpacing.sm,
      ),
      decoration: BoxDecoration(
        color: palette.safeBackground,
        borderRadius: BorderRadius.circular(99),
        border: Border.all(color: AppColors.safe.withValues(alpha: 0.38)),
        boxShadow: [
          BoxShadow(
            color: AppColors.safe.withValues(alpha: 0.12),
            blurRadius: 12,
          ),
        ],
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Container(
            width: 7,
            height: 7,
            decoration: const BoxDecoration(
              color: AppColors.safe,
              shape: BoxShape.circle,
            ),
          ),
          const SizedBox(width: 6),
          const Text(
            'Active',
            style: TextStyle(
              color: AppColors.safe,
              fontSize: 11,
              fontWeight: FontWeight.w700,
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildSectionHeading({
    required String title,
    required String subtitle,
  }) {
    final textTheme = Theme.of(context).textTheme;
    final palette = context.qrPalette;

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          title,
          style: textTheme.titleLarge?.copyWith(
            color: palette.textPrimary,
            fontSize: 20,
            fontWeight: FontWeight.w700,
            letterSpacing: -0.25,
          ),
        ),
        const SizedBox(height: AppSpacing.xs),
        Text(
          subtitle,
          style: textTheme.bodySmall?.copyWith(
            color: palette.textSecondary,
            fontSize: 12,
            fontWeight: FontWeight.w600,
          ),
        ),
      ],
    );
  }

  Widget _buildStatisticsGrid({
    required int totalScans,
    required int highRisk,
    required int lowRisk,
    required int mediumRisk,
  }) {
    return LayoutBuilder(
      builder: (context, constraints) {
        return Align(
          alignment: Alignment.center,
          child: ConstrainedBox(
            constraints: const BoxConstraints(maxWidth: 720),
            child: GridView.count(
              shrinkWrap: true,
              physics: const NeverScrollableScrollPhysics(),
              crossAxisCount: 2,
              crossAxisSpacing: AppSpacing.md,
              mainAxisSpacing: 14,
              mainAxisExtent: constraints.maxWidth >= 520 ? 184 : 188,
              children: [
                StatCard(
                  title: 'Total Scans',
                  value: '$totalScans',
                  icon: Icons.qr_code_scanner_rounded,
                  color: AppColors.primaryBlueBright,
                  caption: 'All scans',
                ),
                StatCard(
                  title: 'High Risk',
                  value: '$highRisk',
                  icon: Icons.gpp_maybe_rounded,
                  color: AppColors.danger,
                  caption: 'Requires attention',
                ),
                StatCard(
                  title: 'Low Risk',
                  value: '$lowRisk',
                  icon: Icons.verified_rounded,
                  color: AppColors.safe,
                  caption: 'Verified scans',
                ),
                StatCard(
                  title: 'Medium Risk',
                  value: '$mediumRisk',
                  icon: Icons.security_rounded,
                  color: AppColors.medium,
                  caption: 'Needs review',
                ),
              ],
            ),
          ),
        );
      },
    );
  }

  Widget _buildSecurityOverview({
    required int totalScans,
    required int lowRisk,
    required int mediumRisk,
    required int highRisk,
  }) {
    final textTheme = Theme.of(context).textTheme;
    final palette = context.qrPalette;

    return CyberCard(
      accentColor: AppColors.primaryBlue,
      borderColor: AppColors.primaryBlue.withValues(alpha: 0.34),
      borderRadius: BorderRadius.circular(AppSpacing.xl),
      padding: const EdgeInsets.all(AppSpacing.xl),
      gradient: LinearGradient(
        begin: Alignment.topLeft,
        end: Alignment.bottomRight,
        colors: [
          palette.surfaceElevated,
          AppColors.primaryBlue.withValues(alpha: 0.08),
          palette.surface,
        ],
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Container(
                width: 44,
                height: 44,
                decoration: BoxDecoration(
                  color: palette.primaryBlueSoft,
                  borderRadius: BorderRadius.circular(AppSpacing.radiusMedium),
                  border: Border.all(
                    color: AppColors.primaryBlue.withValues(alpha: 0.28),
                  ),
                ),
                alignment: Alignment.center,
                child: const Icon(
                  Icons.insights_rounded,
                  color: AppColors.primaryBlueBright,
                  size: 23,
                ),
              ),
              const SizedBox(width: AppSpacing.md),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      'Security Overview',
                      style: textTheme.titleLarge?.copyWith(
                        color: palette.textPrimary,
                        fontSize: 20,
                        fontWeight: FontWeight.w700,
                        letterSpacing: -0.25,
                      ),
                    ),
                    const SizedBox(height: 2),
                    Text(
                      'Current risk distribution',
                      style: textTheme.bodySmall?.copyWith(
                        color: palette.textSecondary,
                        fontSize: 12,
                      ),
                    ),
                  ],
                ),
              ),
              _buildOverviewTotalPill(totalScans),
            ],
          ),
          const SizedBox(height: AppSpacing.xxl),
          _buildDistributionRow(
            label: 'Low Risk',
            count: lowRisk,
            total: totalScans,
            color: AppColors.safe,
          ),
          const SizedBox(height: AppSpacing.md),
          _buildDistributionRow(
            label: 'Medium Risk',
            count: mediumRisk,
            total: totalScans,
            color: AppColors.medium,
          ),
          const SizedBox(height: AppSpacing.md),
          _buildDistributionRow(
            label: 'High Risk',
            count: highRisk,
            total: totalScans,
            color: AppColors.danger,
          ),
        ],
      ),
    );
  }

  Widget _buildOverviewTotalPill(int totalScans) {
    final textTheme = Theme.of(context).textTheme;
    final palette = context.qrPalette;

    return Container(
      padding: const EdgeInsets.symmetric(
        horizontal: AppSpacing.sm,
        vertical: 6,
      ),
      decoration: BoxDecoration(
        color: palette.primaryBlueSoft,
        borderRadius: BorderRadius.circular(99),
        border: Border.all(
          color: AppColors.primaryBlue.withValues(alpha: 0.28),
        ),
      ),
      child: Text(
        '$totalScans total',
        style: textTheme.labelMedium?.copyWith(
          color: AppColors.primaryBlueBright,
          fontWeight: FontWeight.w700,
        ),
      ),
    );
  }

  Widget _buildDistributionRow({
    required String label,
    required int count,
    required int total,
    required Color color,
  }) {
    final textTheme = Theme.of(context).textTheme;
    final palette = context.qrPalette;
    final ratio = total <= 0
        ? 0.0
        : (count / total).clamp(0.0, 1.0).toDouble();
    final percentage = (ratio * 100).round();

    return Column(
      children: [
        Row(
          children: [
            Container(
              width: 9,
              height: 9,
              decoration: BoxDecoration(
                color: color,
                shape: BoxShape.circle,
                boxShadow: [
                  BoxShadow(
                    color: color.withValues(alpha: 0.36),
                    blurRadius: 8,
                  ),
                ],
              ),
            ),
            const SizedBox(width: AppSpacing.sm),
            Expanded(
              child: Text(
                label,
                style: textTheme.bodyMedium?.copyWith(
                  color: palette.textSecondary,
                  fontSize: 13,
                  fontWeight: FontWeight.w600,
                ),
              ),
            ),
            Row(
              mainAxisSize: MainAxisSize.min,
              children: [
                Text(
                  '$count',
                  style: textTheme.labelMedium?.copyWith(
                    color: palette.textPrimary,
                    fontWeight: FontWeight.w700,
                  ),
                ),
                const SizedBox(width: AppSpacing.sm),
                Text(
                  '$percentage%',
                  style: textTheme.labelMedium?.copyWith(
                    color: color,
                    fontWeight: FontWeight.w700,
                  ),
                ),
              ],
            ),
          ],
        ),
        const SizedBox(height: AppSpacing.sm),
        ClipRRect(
          borderRadius: BorderRadius.circular(99),
          child: SizedBox(
            height: 11,
            child: Stack(
              fit: StackFit.expand,
              children: [
                ColoredBox(color: palette.surfaceSoft),
                Align(
                  alignment: Alignment.centerLeft,
                  child: FractionallySizedBox(
                    widthFactor: ratio,
                    heightFactor: 1,
                    child: DecoratedBox(
                      decoration: BoxDecoration(
                        gradient: LinearGradient(
                          colors: [color, color.withValues(alpha: 0.72)],
                        ),
                      ),
                    ),
                  ),
                ),
              ],
            ),
          ),
        ),
      ],
    );
  }

  Widget _buildRecentActivity() {
    final textTheme = Theme.of(context).textTheme;
    final palette = context.qrPalette;

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(
          children: [
            Expanded(
              child: Text(
                'Recent Activity',
                style: textTheme.titleLarge?.copyWith(
                  color: palette.textPrimary,
                  fontSize: 20,
                  fontWeight: FontWeight.w700,
                  letterSpacing: -0.25,
                ),
              ),
            ),
            SizedBox(
              height: 40,
              child: TextButton(
                onPressed: widget.onViewAll,
                style: TextButton.styleFrom(
                  foregroundColor: Theme.of(context).colorScheme.secondary,
                  padding: const EdgeInsets.symmetric(
                    horizontal: AppSpacing.sm,
                  ),
                  textStyle: textTheme.labelMedium?.copyWith(
                    fontWeight: FontWeight.w700,
                    letterSpacing: 0.1,
                  ),
                ),
                child: const Row(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    Text('View All'),
                    SizedBox(width: AppSpacing.xs),
                    Icon(Icons.chevron_right_rounded, size: 18),
                  ],
                ),
              ),
            ),
          ],
        ),
        const SizedBox(height: AppSpacing.lg),
        if (scans.isEmpty)
          _buildEmptyActivityState()
        else
          ...scans.take(5).map((scan) {
            return ActivityTile(
              url: _scanText(
                scan['title'] ?? scan['original_url'],
                fallback: 'Unknown',
              ),
              secondaryText: _scanText(
                scan['original_url'] ?? scan['final_url'],
              ),
              thumbnailUrl: _scanText(scan['screenshot']),
              verdict: _scanText(scan['verdict'], fallback: 'No Verdict'),
            );
          }),
      ],
    );
  }

  Widget _buildEmptyActivityState() {
    final textTheme = Theme.of(context).textTheme;
    final palette = context.qrPalette;

    return CyberCard(
      accentColor: AppColors.primaryBlue,
      borderColor: AppColors.primaryBlue.withValues(alpha: 0.28),
      padding: const EdgeInsets.all(AppSpacing.xl),
      borderRadius: BorderRadius.circular(AppSpacing.radiusLarge),
      child: Row(
        children: [
          Container(
            width: 42,
            height: 42,
            decoration: BoxDecoration(
              color: palette.primaryBlueSoft,
              borderRadius: BorderRadius.circular(AppSpacing.radiusSmall),
            ),
            alignment: Alignment.center,
            child: const Icon(
              Icons.qr_code_2_rounded,
              color: AppColors.primaryBlueBright,
            ),
          ),
          const SizedBox(width: AppSpacing.md),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              mainAxisSize: MainAxisSize.min,
              children: [
                Text(
                  'No recent activity',
                  style: textTheme.titleSmall?.copyWith(
                    color: palette.textPrimary,
                    fontWeight: FontWeight.w600,
                  ),
                ),
                const SizedBox(height: 2),
                Text(
                  'Scanned links will appear here.',
                  style: textTheme.bodySmall?.copyWith(
                    color: palette.textSecondary,
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }
}
