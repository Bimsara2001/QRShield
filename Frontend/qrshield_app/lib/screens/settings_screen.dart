import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';

import '../services/api_service.dart';
import '../services/history_service.dart';
import '../services/health_service.dart';
import '../theme/app_colors.dart';
import '../theme/app_spacing.dart';
import '../theme/theme_controller.dart';
import '../widgets/brand_logo.dart';
import '../widgets/cyber_card.dart';
import '../widgets/screen_header.dart';
import 'result_screen.dart';

class SettingsScreen extends StatefulWidget {
  const SettingsScreen({super.key});

  @override
  State<SettingsScreen> createState() => _SettingsScreenState();
}

class _SettingsScreenState extends State<SettingsScreen> {
  bool checkingBackend = true;
  bool backendConnected = false;
  bool controlledTestLoading = false;

  @override
  void initState() {
    super.initState();
    checkBackendStatus();
  }

  Future<void> checkBackendStatus() async {
    setState(() {
      checkingBackend = true;
    });

    final status = await HealthService.checkBackend();

    if (!mounted) return;

    setState(() {
      backendConnected = status;
      checkingBackend = false;
    });
  }

  @override
  Widget build(BuildContext context) {
    final palette = context.qrPalette;
    final themeMode = ThemeControllerScope.of(context).themeMode;

    return Scaffold(
      backgroundColor: palette.background,
      body: SafeArea(
        bottom: false,
        child: LayoutBuilder(
          builder: (context, constraints) {
            final horizontalPadding = constraints.maxWidth >= 600
                ? AppSpacing.xxl
                : AppSpacing.pageHorizontal;

            return Align(
              alignment: Alignment.topCenter,
              child: ConstrainedBox(
                constraints: const BoxConstraints(maxWidth: 980),
                child: SingleChildScrollView(
                  padding: EdgeInsets.fromLTRB(
                    horizontalPadding,
                    AppSpacing.lg,
                    horizontalPadding,
                    AppSpacing.xxxl + 32,
                  ),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      ScreenHeader(
                        title: 'Settings',
                        subtitle:
                            'Manage QRShield preferences and application status',
                        leading: _buildSettingsMark(context),
                        trailing: _buildRefreshButton(context),
                      ),
                      const SizedBox(height: AppSpacing.xxxl),
                      _buildSectionLabel(context, 'APPLICATION'),
                      const SizedBox(height: AppSpacing.sm),
                      _SettingsRow(
                        icon: Icons.info_outline_rounded,
                        iconColor: AppColors.primaryBlueBright,
                        title: 'App Version',
                        subtitle: 'QRShield application release',
                        trailing: const _ValuePill(
                          label: '1.0.0',
                          color: AppColors.primaryBlueBright,
                        ),
                      ),
                      const SizedBox(height: AppSpacing.sm),
                      _buildThemeRow(context, themeMode),
                      const SizedBox(height: AppSpacing.xxl),
                      _buildSectionLabel(context, 'SYSTEM STATUS'),
                      const SizedBox(height: AppSpacing.sm),
                      _buildBackendStatusRow(),
                      if (kDebugMode) ...[
                        const SizedBox(height: AppSpacing.xxl),
                        _buildSectionLabel(context, 'CONTROLLED TEST'),
                        const SizedBox(height: AppSpacing.sm),
                        _buildControlledTestRow(),
                      ],
                      const SizedBox(height: AppSpacing.xxl),
                      _buildSectionLabel(context, 'DATA MANAGEMENT'),
                      const SizedBox(height: AppSpacing.sm),
                      _buildClearHistoryRow(),
                      const SizedBox(height: AppSpacing.sm),
                      _buildPrivacyDataHandlingRow(),
                      const SizedBox(height: AppSpacing.xxxl),
                      _buildBrandCard(context),
                      const SizedBox(height: AppSpacing.lg),
                      Center(
                        child: Text(
                          'QRShield Research Prototype',
                          style: Theme.of(context).textTheme.bodySmall
                              ?.copyWith(
                                color: palette.textMuted,
                                fontWeight: FontWeight.w600,
                                letterSpacing: 0.2,
                              ),
                        ),
                      ),
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

  String _themeLabel(ThemeMode mode) {
    switch (mode) {
      case ThemeMode.light:
        return 'Light';
      case ThemeMode.system:
        return 'System';
      case ThemeMode.dark:
        return 'Dark';
    }
  }

  String _themeDescription(ThemeMode mode) {
    switch (mode) {
      case ThemeMode.light:
        return 'Light security interface';
      case ThemeMode.system:
        return 'Follows your device setting';
      case ThemeMode.dark:
        return 'Dark security interface';
    }
  }

  IconData _themeIcon(ThemeMode mode) {
    switch (mode) {
      case ThemeMode.light:
        return Icons.light_mode_outlined;
      case ThemeMode.system:
        return Icons.settings_suggest_outlined;
      case ThemeMode.dark:
        return Icons.dark_mode_outlined;
    }
  }

  Widget _buildThemeRow(BuildContext context, ThemeMode mode) {
    final themeAccent = Theme.of(context).colorScheme.secondary;

    return _SettingsRow(
      icon: _themeIcon(mode),
      iconColor: themeAccent,
      title: 'Theme',
      subtitle: _themeDescription(mode),
      trailing: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          _ValuePill(label: _themeLabel(mode), color: themeAccent),
          const SizedBox(width: AppSpacing.xs),
          Icon(
            Icons.chevron_right_rounded,
            color: context.qrPalette.textMuted,
            size: 22,
          ),
        ],
      ),
      onTap: () => _showThemeSelector(context, mode),
    );
  }

  Future<void> _showThemeSelector(
    BuildContext context,
    ThemeMode currentMode,
  ) async {
    final controller = ThemeControllerScope.of(context);

    await showModalBottomSheet<void>(
      context: context,
      backgroundColor: Colors.transparent,
      isScrollControlled: false,
      builder: (sheetContext) {
        final palette = sheetContext.qrPalette;

        return SafeArea(
          top: false,
          child: Padding(
            padding: const EdgeInsets.fromLTRB(
              AppSpacing.md,
              0,
              AppSpacing.md,
              AppSpacing.md,
            ),
            child: Align(
              alignment: Alignment.bottomCenter,
              child: ConstrainedBox(
                constraints: const BoxConstraints(maxWidth: 520),
                child: Container(
                  padding: const EdgeInsets.fromLTRB(
                    AppSpacing.lg,
                    AppSpacing.lg,
                    AppSpacing.lg,
                    AppSpacing.md,
                  ),
                  decoration: BoxDecoration(
                    color: palette.surfaceElevated,
                    borderRadius: BorderRadius.circular(
                      AppSpacing.radiusXLarge,
                    ),
                    border: Border.all(color: palette.borderBright),
                    boxShadow: [
                      BoxShadow(
                        color: palette.shadow,
                        blurRadius: 28,
                        offset: const Offset(0, 12),
                      ),
                    ],
                  ),
                  child: Column(
                    mainAxisSize: MainAxisSize.min,
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        'Choose Theme',
                        style: Theme.of(sheetContext).textTheme.titleLarge
                            ?.copyWith(
                              color: palette.textPrimary,
                              fontWeight: FontWeight.w700,
                            ),
                      ),
                      const SizedBox(height: AppSpacing.sm),
                      Text(
                        'Apply a visual mode across QRShield.',
                        style: Theme.of(sheetContext).textTheme.bodySmall
                            ?.copyWith(color: palette.textSecondary),
                      ),
                      const SizedBox(height: AppSpacing.lg),
                      _ThemeOption(
                        label: 'Dark',
                        description: 'Dark security interface',
                        icon: Icons.dark_mode_outlined,
                        isSelected: currentMode == ThemeMode.dark,
                        onTap: () async {
                          await controller.setThemeMode(ThemeMode.dark);
                          if (sheetContext.mounted) {
                            Navigator.of(sheetContext).pop();
                          }
                        },
                      ),
                      const SizedBox(height: AppSpacing.sm),
                      _ThemeOption(
                        label: 'Light',
                        description: 'Light security interface',
                        icon: Icons.light_mode_outlined,
                        isSelected: currentMode == ThemeMode.light,
                        onTap: () async {
                          await controller.setThemeMode(ThemeMode.light);
                          if (sheetContext.mounted) {
                            Navigator.of(sheetContext).pop();
                          }
                        },
                      ),
                      const SizedBox(height: AppSpacing.sm),
                      _ThemeOption(
                        label: 'System Default',
                        description: 'Follow your device setting',
                        icon: Icons.settings_suggest_outlined,
                        isSelected: currentMode == ThemeMode.system,
                        onTap: () async {
                          await controller.setThemeMode(ThemeMode.system);
                          if (sheetContext.mounted) {
                            Navigator.of(sheetContext).pop();
                          }
                        },
                      ),
                    ],
                  ),
                ),
              ),
            ),
          ),
        );
      },
    );
  }

  Widget _buildSettingsMark(BuildContext context) {
    final palette = context.qrPalette;

    return Container(
      width: 42,
      height: 42,
      decoration: BoxDecoration(
        color: palette.primaryBlueSoft,
        borderRadius: BorderRadius.circular(AppSpacing.radiusMedium),
        border: Border.all(color: palette.borderBright),
        boxShadow: [
          BoxShadow(
            color: palette.blueGlow,
            blurRadius: 15,
            offset: Offset(0, 6),
          ),
        ],
      ),
      alignment: Alignment.center,
      child: const Icon(
        Icons.settings_rounded,
        color: AppColors.primaryBlueBright,
        size: 22,
      ),
    );
  }

  Widget _buildRefreshButton(BuildContext context) {
    final palette = context.qrPalette;

    return SizedBox(
      width: 42,
      height: 42,
      child: DecoratedBox(
        decoration: BoxDecoration(
          color: palette.surfaceElevated,
          shape: BoxShape.circle,
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
          tooltip: 'Refresh backend status',
          padding: EdgeInsets.zero,
          style: IconButton.styleFrom(
            minimumSize: const Size.square(42),
            shape: const CircleBorder(),
          ),
          onPressed: checkBackendStatus,
          icon: checkingBackend
              ? const SizedBox(
                  width: 18,
                  height: 18,
                  child: CircularProgressIndicator(strokeWidth: 2),
                )
              : const Icon(
                  Icons.refresh_rounded,
                  color: AppColors.primaryBlueBright,
                  size: 21,
                ),
        ),
      ),
    );
  }

  Widget _buildSectionLabel(BuildContext context, String label) {
    return Text(
      label,
      style: Theme.of(context).textTheme.labelMedium?.copyWith(
        color: context.qrPalette.textMuted,
        fontWeight: FontWeight.w700,
        letterSpacing: 1.1,
      ),
    );
  }

  Widget _buildBackendStatusRow() {
    final statusColor = checkingBackend
        ? AppColors.primaryBlueBright
        : backendConnected
        ? AppColors.safe
        : AppColors.danger;
    final statusIcon = checkingBackend
        ? Icons.cloud_sync_outlined
        : backendConnected
        ? Icons.cloud_done_rounded
        : Icons.cloud_off_rounded;
    final statusText = checkingBackend
        ? 'Checking...'
        : backendConnected
        ? 'Connected'
        : 'Disconnected';
    final statusPill = checkingBackend
        ? 'Checking'
        : backendConnected
        ? 'Live'
        : 'Offline';

    return _SettingsRow(
      icon: statusIcon,
      iconColor: statusColor,
      title: 'Backend Status',
      subtitle: statusText,
      trailing: _StatusPill(
        label: statusPill,
        color: statusColor,
        isLoading: checkingBackend,
      ),
      accentColor: statusColor,
    );
  }

  Widget _buildControlledTestRow() {
    return _SettingsRow(
      icon: Icons.science_outlined,
      iconColor: AppColors.danger,
      title: 'Run Controlled High-Risk Test',
      subtitle: 'Test the High Risk result UI using a safe local fixture',
      accentColor: AppColors.danger,
      trailing: controlledTestLoading
          ? const SizedBox(
              width: 20,
              height: 20,
              child: CircularProgressIndicator(strokeWidth: 2),
            )
          : const Icon(
              Icons.chevron_right_rounded,
              color: AppColors.danger,
              size: 24,
            ),
      onTap: controlledTestLoading ? null : _runControlledHighRiskTest,
    );
  }

  Future<void> _runControlledHighRiskTest() async {
    if (controlledTestLoading) return;

    setState(() {
      controlledTestLoading = true;
    });

    try {
      final result = await ApiService.runControlledHighRiskTest();
      if (!mounted) return;

      setState(() {
        controlledTestLoading = false;
      });

      await Navigator.push(
        context,
        MaterialPageRoute<void>(builder: (_) => ResultScreen(result: result)),
      );
    } on ScanException catch (error) {
      if (!mounted) return;
      setState(() {
        controlledTestLoading = false;
      });
      ScaffoldMessenger.of(
        context,
      ).showSnackBar(SnackBar(content: Text(error.message)));
    } catch (_) {
      if (!mounted) return;
      setState(() {
        controlledTestLoading = false;
      });
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          content: Text('Unable to complete controlled security test.'),
        ),
      );
    }
  }

  Widget _buildClearHistoryRow() {
    return _SettingsRow(
      icon: Icons.delete_outline_rounded,
      iconColor: AppColors.danger,
      title: 'Clear History',
      subtitle: 'Delete all saved scan history',
      accentColor: AppColors.danger,
      trailing: const Icon(
        Icons.chevron_right_rounded,
        color: AppColors.danger,
        size: 24,
      ),
      onTap: () async {
        final confirm = await showDialog<bool>(
          context: context,
          builder: (context) {
            final palette = context.qrPalette;

            return AlertDialog(
              backgroundColor: palette.surfaceElevated,
              surfaceTintColor: Colors.transparent,
              shape: RoundedRectangleBorder(
                borderRadius: BorderRadius.circular(AppSpacing.radiusLarge),
                side: BorderSide(
                  color: AppColors.danger.withValues(alpha: 0.38),
                ),
              ),
              title: Row(
                children: [
                  Container(
                    width: 40,
                    height: 40,
                    decoration: BoxDecoration(
                      color: palette.dangerBackground,
                      borderRadius: BorderRadius.circular(
                        AppSpacing.radiusSmall,
                      ),
                      border: Border.all(
                        color: AppColors.danger.withValues(alpha: 0.30),
                      ),
                    ),
                    alignment: Alignment.center,
                    child: const Icon(
                      Icons.delete_forever_outlined,
                      color: AppColors.danger,
                      size: 22,
                    ),
                  ),
                  const SizedBox(width: AppSpacing.md),
                  const Expanded(child: Text('Clear scan history?')),
                ],
              ),
              content: Text(
                'This will remove saved scan history and attempt to remove its associated QRShield screenshots.',
                style: TextStyle(color: palette.textSecondary, height: 1.45),
              ),
              actionsPadding: const EdgeInsets.fromLTRB(
                AppSpacing.lg,
                0,
                AppSpacing.lg,
                AppSpacing.lg,
              ),
              actions: [
                TextButton(
                  onPressed: () {
                    Navigator.pop(context, false);
                  },
                  child: const Text('Cancel'),
                ),
                FilledButton(
                  onPressed: () {
                    Navigator.pop(context, true);
                  },
                  style: FilledButton.styleFrom(
                    backgroundColor: AppColors.danger,
                    foregroundColor: Colors.white,
                  ),
                  child: const Text('Clear History'),
                ),
              ],
            );
          },
        );

        if (confirm != true) return;

        final success = await HistoryService.clearHistory();

        if (!context.mounted) return;

        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text(
              success
                  ? 'History cleared successfully'
                  : 'Failed to clear history',
            ),
          ),
        );
      },
    );
  }

  Widget _buildPrivacyDataHandlingRow() {
    return _SettingsRow(
      icon: Icons.privacy_tip_outlined,
      iconColor: AppColors.primaryBlueBright,
      title: 'Privacy & Data Handling',
      subtitle: 'Review stored scan data and external checks',
      trailing: const Icon(
        Icons.chevron_right_rounded,
        color: AppColors.primaryBlueBright,
        size: 24,
      ),
      onTap: () {
        showDialog<void>(
          context: context,
          builder: (dialogContext) => AlertDialog(
            title: const Text('Privacy & Data Handling'),
            content: const SingleChildScrollView(
              child: Text(
                'QRShield stores scanned and final URLs, result details, and a preview screenshot in backend scan history so you can review results. URLs and screenshots may contain personal information.\n\n'
                'Clear History removes saved history and attempts to remove associated QRShield screenshots. History remains until you clear it. QRShield does not intentionally request names, email addresses, participant IDs, or device identifiers.\n\n'
                'When configured, QRShield sends the final URL to VirusTotal for supplementary threat intelligence. This research prototype cannot guarantee deletion from third-party services, infrastructure logs, or backups.',
              ),
            ),
            actions: [
              TextButton(
                onPressed: () => Navigator.pop(dialogContext),
                child: const Text('Close'),
              ),
            ],
          ),
        );
      },
    );
  }

  Widget _buildBrandCard(BuildContext context) {
    final textTheme = Theme.of(context).textTheme;
    final palette = context.qrPalette;

    return CyberCard(
      accentColor: AppColors.primaryBlue,
      borderColor: AppColors.primaryBlue.withValues(alpha: 0.40),
      padding: const EdgeInsets.all(AppSpacing.xl),
      gradient: LinearGradient(
        begin: Alignment.topLeft,
        end: Alignment.bottomRight,
        colors: [
          palette.surfaceElevated,
          AppColors.primaryBlue.withValues(alpha: 0.12),
          palette.surface,
        ],
      ),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const BrandLogo(size: 52),
          const SizedBox(width: AppSpacing.md),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  'QRShield',
                  style: textTheme.titleLarge?.copyWith(
                    color: palette.textPrimary,
                    fontWeight: FontWeight.w700,
                  ),
                ),
                const SizedBox(height: AppSpacing.xs),
                Text(
                  'QR Code Threat Detection Platform',
                  style: textTheme.labelLarge?.copyWith(
                    color: AppColors.primaryBlueBright,
                    fontWeight: FontWeight.w600,
                  ),
                ),
                const SizedBox(height: AppSpacing.sm),
                Text(
                  'A Zero-Trust inspired security framework for analyzing QR-delivered web threats before direct navigation.',
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
}

class _SettingsRow extends StatelessWidget {
  final IconData icon;
  final Color iconColor;
  final String title;
  final String subtitle;
  final Widget? trailing;
  final Color? accentColor;
  final VoidCallback? onTap;

  const _SettingsRow({
    required this.icon,
    required this.iconColor,
    required this.title,
    required this.subtitle,
    this.trailing,
    this.accentColor,
    this.onTap,
  });

  @override
  Widget build(BuildContext context) {
    final textTheme = Theme.of(context).textTheme;
    final palette = context.qrPalette;
    final resolvedAccent = accentColor ?? iconColor;
    final content = Padding(
      padding: const EdgeInsets.all(AppSpacing.lg),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.center,
        children: [
          Container(
            width: 42,
            height: 42,
            decoration: BoxDecoration(
              color: iconColor.withValues(alpha: 0.12),
              borderRadius: BorderRadius.circular(AppSpacing.radiusMedium),
              border: Border.all(color: iconColor.withValues(alpha: 0.24)),
            ),
            alignment: Alignment.center,
            child: Icon(icon, color: iconColor, size: 22),
          ),
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
                  style: textTheme.titleMedium?.copyWith(
                    color: palette.textPrimary,
                    fontWeight: FontWeight.w700,
                  ),
                ),
                const SizedBox(height: AppSpacing.xs),
                Text(
                  subtitle,
                  maxLines: 2,
                  overflow: TextOverflow.ellipsis,
                  style: textTheme.bodySmall?.copyWith(
                    color: palette.textSecondary,
                    height: 1.35,
                  ),
                ),
              ],
            ),
          ),
          if (trailing != null) ...[
            const SizedBox(width: AppSpacing.md),
            trailing!,
          ],
        ],
      ),
    );

    return CyberCard(
      accentColor: resolvedAccent,
      borderColor: resolvedAccent.withValues(alpha: 0.24),
      padding: EdgeInsets.zero,
      child: onTap == null
          ? content
          : Material(
              color: Colors.transparent,
              borderRadius: BorderRadius.circular(AppSpacing.radiusLarge),
              clipBehavior: Clip.antiAlias,
              child: InkWell(onTap: onTap, child: content),
            ),
    );
  }
}

class _ThemeOption extends StatelessWidget {
  final String label;
  final String description;
  final IconData icon;
  final bool isSelected;
  final VoidCallback onTap;

  const _ThemeOption({
    required this.label,
    required this.description,
    required this.icon,
    required this.isSelected,
    required this.onTap,
  });

  @override
  Widget build(BuildContext context) {
    final palette = context.qrPalette;
    final textTheme = Theme.of(context).textTheme;
    final accent = Theme.of(context).colorScheme.secondary;

    return Material(
      color: Colors.transparent,
      borderRadius: BorderRadius.circular(AppSpacing.radiusMedium),
      clipBehavior: Clip.antiAlias,
      child: InkWell(
        onTap: onTap,
        child: AnimatedContainer(
          duration: const Duration(milliseconds: 180),
          padding: const EdgeInsets.all(AppSpacing.md),
          decoration: BoxDecoration(
            color: isSelected ? palette.primaryBlueSoft : palette.surface,
            borderRadius: BorderRadius.circular(AppSpacing.radiusMedium),
            border: Border.all(
              color: isSelected
                  ? AppColors.primaryBlue.withValues(alpha: 0.48)
                  : palette.border,
            ),
          ),
          child: Row(
            children: [
              Container(
                width: 40,
                height: 40,
                decoration: BoxDecoration(
                  color: accent.withValues(alpha: 0.12),
                  borderRadius: BorderRadius.circular(AppSpacing.radiusSmall),
                ),
                alignment: Alignment.center,
                child: Icon(icon, color: accent, size: 21),
              ),
              const SizedBox(width: AppSpacing.md),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      label,
                      style: textTheme.titleSmall?.copyWith(
                        color: palette.textPrimary,
                        fontWeight: FontWeight.w700,
                      ),
                    ),
                    const SizedBox(height: 2),
                    Text(
                      description,
                      style: textTheme.bodySmall?.copyWith(
                        color: palette.textSecondary,
                      ),
                    ),
                  ],
                ),
              ),
              const SizedBox(width: AppSpacing.sm),
              AnimatedContainer(
                duration: const Duration(milliseconds: 180),
                width: 22,
                height: 22,
                decoration: BoxDecoration(
                  color: isSelected ? accent : Colors.transparent,
                  shape: BoxShape.circle,
                  border: Border.all(
                    color: isSelected ? accent : palette.borderBright,
                    width: 1.5,
                  ),
                ),
                alignment: Alignment.center,
                child: isSelected
                    ? const Icon(
                        Icons.check_rounded,
                        color: Colors.white,
                        size: 15,
                      )
                    : null,
              ),
            ],
          ),
        ),
      ),
    );
  }
}

class _ValuePill extends StatelessWidget {
  final String label;
  final Color color;

  const _ValuePill({required this.label, required this.color});

  @override
  Widget build(BuildContext context) {
    final textTheme = Theme.of(context).textTheme;

    return Container(
      padding: const EdgeInsets.symmetric(
        horizontal: AppSpacing.sm,
        vertical: 6,
      ),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.10),
        borderRadius: BorderRadius.circular(99),
        border: Border.all(color: color.withValues(alpha: 0.24)),
      ),
      child: Text(
        label,
        style: textTheme.labelMedium?.copyWith(
          color: color,
          fontWeight: FontWeight.w700,
        ),
      ),
    );
  }
}

class _StatusPill extends StatelessWidget {
  final String label;
  final Color color;
  final bool isLoading;

  const _StatusPill({
    required this.label,
    required this.color,
    required this.isLoading,
  });

  @override
  Widget build(BuildContext context) {
    final textTheme = Theme.of(context).textTheme;

    return Container(
      padding: const EdgeInsets.symmetric(
        horizontal: AppSpacing.sm,
        vertical: 6,
      ),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.12),
        borderRadius: BorderRadius.circular(99),
        border: Border.all(color: color.withValues(alpha: 0.28)),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          if (isLoading)
            SizedBox(
              width: 11,
              height: 11,
              child: CircularProgressIndicator(strokeWidth: 1.8, color: color),
            )
          else
            Container(
              width: 7,
              height: 7,
              decoration: BoxDecoration(
                color: color,
                shape: BoxShape.circle,
                boxShadow: [
                  BoxShadow(
                    color: color.withValues(alpha: 0.35),
                    blurRadius: 7,
                  ),
                ],
              ),
            ),
          const SizedBox(width: 6),
          Text(
            label,
            style: textTheme.labelMedium?.copyWith(
              color: color,
              fontWeight: FontWeight.w700,
            ),
          ),
        ],
      ),
    );
  }
}
