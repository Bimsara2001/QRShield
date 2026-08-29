import 'package:flutter/material.dart';

import '../services/history_service.dart';
import '../services/api_service.dart';
import '../theme/app_colors.dart';
import '../theme/app_spacing.dart';
import '../widgets/cyber_card.dart';
import '../widgets/risk_badge.dart';
import '../widgets/screen_header.dart';
import 'result_screen.dart';

class HistoryScreen extends StatefulWidget {
  const HistoryScreen({super.key});

  @override
  State<HistoryScreen> createState() => _HistoryScreenState();
}

class _HistoryScreenState extends State<HistoryScreen> {
  List scans = [];

  bool loading = true;

  String searchQuery = "";
  String selectedFilter = "All";

  @override
  void initState() {
    super.initState();
    loadHistory();
  }

  Future<void> loadHistory() async {
    try {
      final data = await HistoryService.getHistory();

      setState(() {
        scans = data;
        loading = false;
      });
    } catch (e) {
      print("===== HISTORY ERROR =====");
      print(e);

      setState(() {
        loading = false;
      });
    }
  }

  List get filteredScans {
    return scans.where((scan) {
      final title = (scan["title"] ?? "").toString().toLowerCase();

      final url = (scan["original_url"] ?? "").toString().toLowerCase();

      final verdict = (scan["verdict"] ?? "").toString();

      final matchesSearch =
          title.contains(searchQuery.toLowerCase()) ||
          url.contains(searchQuery.toLowerCase());

      final matchesFilter = selectedFilter == "All"
          ? true
          : verdict == selectedFilter;

      return matchesSearch && matchesFilter;
    }).toList();
  }

  Color _filterAccent(String label) {
    switch (label) {
      case 'Low Risk':
        return AppColors.safe;
      case 'Medium Risk':
        return AppColors.medium;
      case 'High Risk':
        return AppColors.danger;
      default:
        return AppColors.primaryBlueBright;
    }
  }

  Widget filterChip(String label) {
    final selected = selectedFilter == label;
    final accent = _filterAccent(label);
    final textTheme = Theme.of(context).textTheme;
    final palette = context.qrPalette;

    return Material(
      color: Colors.transparent,
      child: InkWell(
        borderRadius: BorderRadius.circular(AppSpacing.radiusMedium),
        onTap: () {
          setState(() {
            selectedFilter = label;
          });
        },
        child: AnimatedContainer(
          duration: const Duration(milliseconds: 180),
          curve: Curves.easeOutCubic,
          padding: const EdgeInsets.symmetric(
            horizontal: AppSpacing.md,
            vertical: AppSpacing.sm,
          ),
          decoration: BoxDecoration(
            color: selected ? AppColors.primaryBlue : palette.surfaceElevated,
            borderRadius: BorderRadius.circular(AppSpacing.radiusMedium),
            border: Border.all(
              color: selected
                  ? AppColors.primaryBlueBright.withValues(alpha: 0.70)
                  : palette.border,
            ),
            boxShadow: selected
                ? [
                    BoxShadow(
                      color: AppColors.primaryBlue.withValues(alpha: 0.18),
                      blurRadius: 14,
                      offset: const Offset(0, 5),
                    ),
                  ]
                : null,
          ),
          child: Row(
            mainAxisSize: MainAxisSize.min,
            children: [
              if (selected) ...[
                const Icon(Icons.check_rounded, color: Colors.white, size: 16),
                const SizedBox(width: 5),
              ],
              Container(
                width: 7,
                height: 7,
                decoration: BoxDecoration(
                  color: accent,
                  shape: BoxShape.circle,
                ),
              ),
              const SizedBox(width: 6),
              Text(
                label,
                style: textTheme.labelMedium?.copyWith(
                  color: selected ? Colors.white : palette.textSecondary,
                  fontWeight: FontWeight.w700,
                ),
              ),
            ],
          ),
        ),
      ),
    );
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
      body: SafeArea(
        bottom: false,
        child: LayoutBuilder(
          builder: (context, constraints) {
            final pagePadding = constraints.maxWidth >= 600
                ? AppSpacing.xxl
                : AppSpacing.pageHorizontal;

            return Align(
              alignment: Alignment.topCenter,
              child: ConstrainedBox(
                constraints: const BoxConstraints(maxWidth: 1000),
                child: Column(
                  children: [
                    Padding(
                      padding: EdgeInsets.fromLTRB(
                        pagePadding,
                        AppSpacing.lg,
                        pagePadding,
                        AppSpacing.lg,
                      ),
                      child: ScreenHeader(
                        title: 'Scan History',
                        subtitle:
                            'Review previously analyzed QR codes and URLs',
                        leading: _buildHistoryMark(),
                      ),
                    ),
                    Padding(
                      padding: EdgeInsets.symmetric(horizontal: pagePadding),
                      child: TextField(
                        style: TextStyle(color: palette.textPrimary),
                        decoration: InputDecoration(
                          hintText: 'Search by URL or title...',
                          prefixIcon: Icon(
                            Icons.search_rounded,
                            color: palette.textMuted,
                          ),
                        ),
                        onChanged: (value) {
                          setState(() {
                            searchQuery = value;
                          });
                        },
                      ),
                    ),
                    const SizedBox(height: AppSpacing.md),
                    SingleChildScrollView(
                      scrollDirection: Axis.horizontal,
                      padding: EdgeInsets.symmetric(horizontal: pagePadding),
                      child: Row(
                        children: [
                          filterChip("All"),
                          const SizedBox(width: AppSpacing.sm),
                          filterChip("Low Risk"),
                          const SizedBox(width: AppSpacing.sm),
                          filterChip("Medium Risk"),
                          const SizedBox(width: AppSpacing.sm),
                          filterChip("High Risk"),
                        ],
                      ),
                    ),
                    const SizedBox(height: AppSpacing.sm),
                    Expanded(
                      child: loading
                          ? _buildLoadingState()
                          : _buildHistoryList(pagePadding),
                    ),
                  ],
                ),
              ),
            );
          },
        ),
      ),
    );
  }

  Widget _buildHistoryMark() {
    final palette = context.qrPalette;

    return Container(
      width: 42,
      height: 42,
      decoration: BoxDecoration(
        borderRadius: BorderRadius.circular(AppSpacing.radiusMedium),
        color: palette.primaryBlueSoft,
        border: Border.all(color: palette.borderBright),
        boxShadow: [
          BoxShadow(
            color: palette.blueGlow,
            blurRadius: 14,
            offset: Offset(0, 6),
          ),
        ],
      ),
      alignment: Alignment.center,
      child: const Icon(
        Icons.history_rounded,
        color: AppColors.primaryBlueBright,
        size: 22,
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
            'Loading scan history...',
            style: TextStyle(color: palette.textSecondary),
          ),
        ],
      ),
    );
  }

  Widget _buildHistoryList(double pagePadding) {
    final palette = context.qrPalette;

    return RefreshIndicator(
      onRefresh: loadHistory,
      color: AppColors.primaryBlue,
      backgroundColor: palette.surfaceElevated,
      child: filteredScans.isEmpty
          ? ListView(
              padding: EdgeInsets.fromLTRB(
                pagePadding,
                96,
                pagePadding,
                AppSpacing.xxxl + 36,
              ),
              children: [_buildEmptyState(hasHistory: scans.isNotEmpty)],
            )
          : ListView.builder(
              padding: EdgeInsets.fromLTRB(
                pagePadding,
                AppSpacing.sm,
                pagePadding,
                AppSpacing.xxxl + 36,
              ),
              itemCount: filteredScans.length,
              itemBuilder: (context, index) {
                final scan = filteredScans[index];

                return _buildHistoryEntry(scan);
              },
            ),
    );
  }

  Widget _buildEmptyState({required bool hasHistory}) {
    final textTheme = Theme.of(context).textTheme;
    final palette = context.qrPalette;
    final title = hasHistory ? 'No matching scans' : 'No scans yet';
    final message = hasHistory
        ? 'Try changing your search or risk filter.'
        : 'Your analyzed QR codes and URLs will appear here.';

    return CyberCard(
      accentColor: AppColors.primaryBlue,
      padding: const EdgeInsets.all(AppSpacing.xl),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          Container(
            width: 58,
            height: 58,
            decoration: BoxDecoration(
              color: palette.primaryBlueSoft,
              shape: BoxShape.circle,
              border: Border.all(
                color: AppColors.primaryBlue.withValues(alpha: 0.26),
              ),
            ),
            alignment: Alignment.center,
            child: Icon(
              hasHistory
                  ? Icons.search_off_rounded
                  : Icons.history_toggle_off_rounded,
              color: AppColors.primaryBlueBright,
              size: 27,
            ),
          ),
          const SizedBox(height: AppSpacing.lg),
          Text(
            title,
            style: textTheme.titleMedium?.copyWith(
              color: palette.textPrimary,
              fontWeight: FontWeight.w700,
            ),
          ),
          const SizedBox(height: AppSpacing.sm),
          Text(
            message,
            textAlign: TextAlign.center,
            style: textTheme.bodyMedium?.copyWith(
              color: palette.textSecondary,
              height: 1.4,
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildHistoryEntry(dynamic scan) {
    final palette = context.qrPalette;
    final verdict = _scanText(scan['verdict'], fallback: 'No Verdict');
    final riskColor = RiskBadge.colorForVerdict(verdict);
    final title = _scanText(
      scan['title'],
      fallback: _scanText(scan['original_url'], fallback: 'Unknown'),
    );
    final url = _scanText(scan['original_url'] ?? scan['final_url']);
    final screenshot = _scanText(scan['screenshot']);
    final riskScore = _scanText(scan['risk_score'], fallback: '-');

    return CyberCard(
      margin: const EdgeInsets.only(bottom: AppSpacing.md),
      padding: EdgeInsets.zero,
      accentColor: riskColor,
      borderColor: riskColor.withValues(alpha: 0.28),
      borderRadius: BorderRadius.circular(AppSpacing.radiusMedium),
      child: Material(
        type: MaterialType.transparency,
        child: InkWell(
          borderRadius: BorderRadius.circular(AppSpacing.radiusMedium),
          onTap: () {
            Navigator.push(
              context,
              MaterialPageRoute(builder: (_) => ResultScreen(result: scan)),
            );
          },
          child: Padding(
            padding: const EdgeInsets.all(AppSpacing.md),
            child: Row(
              crossAxisAlignment: CrossAxisAlignment.center,
              children: [
                _HistoryThumbnail(imageUrl: screenshot, accentColor: riskColor),
                const SizedBox(width: AppSpacing.md),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      Text(
                        title,
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                        style: Theme.of(context).textTheme.titleSmall?.copyWith(
                          color: palette.textPrimary,
                          fontWeight: FontWeight.w700,
                        ),
                      ),
                      const SizedBox(height: 5),
                      Wrap(
                        spacing: AppSpacing.sm,
                        runSpacing: 5,
                        crossAxisAlignment: WrapCrossAlignment.center,
                        children: [
                          RiskBadge(verdict: verdict, compact: true),
                          Text(
                            'Risk score: $riskScore',
                            style: Theme.of(context).textTheme.bodySmall
                                ?.copyWith(
                                  color: palette.textSecondary,
                                  fontWeight: FontWeight.w600,
                                ),
                          ),
                        ],
                      ),
                      if (url.isNotEmpty) ...[
                        const SizedBox(height: 5),
                        Text(
                          url,
                          maxLines: 1,
                          overflow: TextOverflow.ellipsis,
                          style: Theme.of(context).textTheme.bodySmall
                              ?.copyWith(color: palette.textMuted),
                        ),
                      ],
                    ],
                  ),
                ),
                const SizedBox(width: AppSpacing.xs),
                Icon(
                  Icons.chevron_right_rounded,
                  color: palette.textMuted.withValues(alpha: 0.80),
                  size: 22,
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}

class _HistoryThumbnail extends StatelessWidget {
  final String imageUrl;
  final Color accentColor;

  const _HistoryThumbnail({required this.imageUrl, required this.accentColor});

  @override
  Widget build(BuildContext context) {
    final radius = BorderRadius.circular(AppSpacing.radiusSmall);

    return SizedBox(
      width: 64,
      height: 64,
      child: ClipRRect(
        borderRadius: radius,
        child: imageUrl.isEmpty
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
      child: Icon(Icons.language_rounded, color: accentColor, size: 26),
    );
  }
}
