import 'package:flutter/material.dart';
import 'package:mobile_scanner/mobile_scanner.dart';

import '../services/api_service.dart';
import '../theme/app_colors.dart';
import '../theme/app_spacing.dart';
import '../widgets/brand_logo.dart';
import '../widgets/cyber_card.dart';
import '../widgets/scanner_frame.dart';
import '../widgets/screen_header.dart';
import 'result_screen.dart';

class ScanScreen extends StatefulWidget {
  const ScanScreen({super.key});

  @override
  State<ScanScreen> createState() => _ScanScreenState();
}

class _ScanScreenState extends State<ScanScreen> {
  bool scanned = false;
  bool loading = false;
  String? analysisError;
  String? failedUrl;

  final TextEditingController urlController = TextEditingController();

  Future<void> analyzeUrl(String url) async {
    if (loading) return;

    if (url.trim().isEmpty) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          content: Text("Please enter a URL"),
        ),
      );
      return;
    }

    setState(() {
      loading = true;
      analysisError = null;
      failedUrl = null;
    });

    try {
      final result = await ApiService.scanUrl(url.trim());

      if (!mounted) return;

      setState(() {
        loading = false;
        analysisError = null;
      });

      Navigator.push(
        context,
        MaterialPageRoute(
          builder: (_) => ResultScreen(
            result: result,
          ),
        ),
      ).then((_) {
        scanned = false;
      });
    } catch (_) {
      if (!mounted) return;

      setState(() {
        loading = false;
        analysisError = 'Unable to complete security analysis. Please try again.';
        failedUrl = url.trim();
      });

      scanned = false;
    }
  }

  @override
  void dispose() {
    urlController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final palette = context.qrPalette;

    return Scaffold(
      backgroundColor: palette.background,
      body: Stack(
        children: [
          SafeArea(
            bottom: false,
            child: LayoutBuilder(
              builder: (context, constraints) {
                final horizontalPadding = constraints.maxWidth >= 600
                    ? AppSpacing.xxl
                    : AppSpacing.pageHorizontal;
                final availableScannerWidth =
                    constraints.maxWidth - (horizontalPadding * 2);
                final scannerMaxSize =
                    constraints.maxWidth >= 600 ? 420.0 : 300.0;
                final scannerSize = availableScannerWidth
                    .clamp(0.0, scannerMaxSize)
                    .toDouble();

                return Align(
                  alignment: Alignment.topCenter,
                  child: ConstrainedBox(
                    constraints: const BoxConstraints(maxWidth: 960),
                    child: SingleChildScrollView(
                      padding: EdgeInsets.fromLTRB(
                        horizontalPadding,
                        AppSpacing.lg,
                        horizontalPadding,
                        AppSpacing.xxxl,
                      ),
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          ScreenHeader(
                            title: 'QRShield',
                            subtitle: 'Advanced QR Threat Detection',
                            leading: _buildBrandMark(),
                          ),
                          const SizedBox(height: AppSpacing.xxxl),
                          _buildScanIntroduction(),
                          const SizedBox(height: AppSpacing.xl),
                          Center(
                            child: _buildScannerViewport(scannerSize),
                          ),
                          const SizedBox(height: AppSpacing.md),
                          Center(child: _buildScannerHelper()),
                          const SizedBox(height: AppSpacing.xxl),
                          _buildManualUrlCard(),
                          const SizedBox(height: AppSpacing.xxl),
                          _buildSecurityFeaturesCard(),
                        ],
                      ),
                    ),
                  ),
                );
              },
            ),
          ),
          if (loading) _buildLoadingOverlay(),
          if (analysisError != null) _buildAnalysisFailureOverlay(),
        ],
      ),
    );
  }

  Widget _buildBrandMark() {
    return BrandLogo(
      size: MediaQuery.sizeOf(context).width >= 600 ? 52 : 48,
    );
  }

  Widget _buildScanIntroduction() {
    final textTheme = Theme.of(context).textTheme;
    final palette = context.qrPalette;

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          'Scan Any QR Code',
          style: textTheme.headlineSmall?.copyWith(
            color: palette.textPrimary,
            fontSize: 24,
            fontWeight: FontWeight.w700,
            letterSpacing: -0.35,
          ),
        ),
        const SizedBox(height: AppSpacing.xs),
        Text(
          'Instantly analyze and detect hidden threats',
          style: textTheme.bodyMedium?.copyWith(
            color: palette.textSecondary,
            fontWeight: FontWeight.w500,
          ),
        ),
      ],
    );
  }

  Widget _buildScannerViewport(double scannerSize) {
    return ScannerFrame(
      size: scannerSize,
      child: MobileScanner(
        controller: MobileScannerController(
          formats: [
            BarcodeFormat.qrCode,
          ],
          detectionSpeed: DetectionSpeed.noDuplicates,
        ),
        onDetect: (capture) async {
          if (scanned || loading) return;

          if (capture.barcodes.isEmpty) {
            return;
          }

          final barcode = capture.barcodes.first;

          final url = barcode.rawValue ?? "";

          if (url.isEmpty) {
            return;
          }

          scanned = true;

          await analyzeUrl(url);
        },
      ),
    );
  }

  Widget _buildScannerHelper() {
    final textTheme = Theme.of(context).textTheme;
    final palette = context.qrPalette;

    return Container(
      constraints: const BoxConstraints(maxWidth: 420),
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
          const Icon(
            Icons.shield_outlined,
            color: AppColors.primaryBlueBright,
            size: 18,
          ),
          const SizedBox(width: AppSpacing.sm),
          Flexible(
            child: Text(
              'Position the QR code within the frame to scan',
              textAlign: TextAlign.center,
              style: textTheme.bodySmall?.copyWith(
                color: palette.textSecondary,
                fontWeight: FontWeight.w500,
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildManualUrlCard() {
    final textTheme = Theme.of(context).textTheme;
    final palette = context.qrPalette;

    return CyberCard(
      accentColor: AppColors.primaryBlue,
      borderColor: palette.borderBright,
      padding: const EdgeInsets.all(AppSpacing.lg),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Container(
                width: 38,
                height: 38,
                decoration: BoxDecoration(
                  color: palette.primaryBlueSoft,
                  borderRadius: BorderRadius.circular(AppSpacing.radiusSmall),
                  border: Border.all(
                    color: AppColors.primaryBlue.withValues(alpha: 0.28),
                  ),
                ),
                alignment: Alignment.center,
                child: const Icon(
                  Icons.link_rounded,
                  color: AppColors.primaryBlueBright,
                  size: 20,
                ),
              ),
              const SizedBox(width: AppSpacing.md),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      'Enter URL manually',
                      style: textTheme.titleMedium?.copyWith(
                        color: palette.textPrimary,
                        fontWeight: FontWeight.w700,
                      ),
                    ),
                    const SizedBox(height: 2),
                    Text(
                      'Scan a URL instead of a QR code',
                      style: textTheme.bodySmall?.copyWith(
                        color: palette.textSecondary,
                      ),
                    ),
                  ],
                ),
              ),
            ],
          ),
          const SizedBox(height: AppSpacing.lg),
          TextField(
            controller: urlController,
            style: TextStyle(color: palette.textPrimary),
            decoration: InputDecoration(
              hintText: 'https://example.com',
              prefixIcon: Icon(
                Icons.link_rounded,
                color: palette.textMuted,
              ),
            ),
          ),
          const SizedBox(height: AppSpacing.md),
          SizedBox(
            width: double.infinity,
            child: ElevatedButton.icon(
              onPressed: () {
                analyzeUrl(
                  urlController.text,
                );
              },
              style: ElevatedButton.styleFrom(
                backgroundColor: AppColors.primaryBlue,
                foregroundColor: Colors.white,
                minimumSize: const Size.fromHeight(48),
                shape: RoundedRectangleBorder(
                  borderRadius: BorderRadius.circular(AppSpacing.radiusMedium),
                ),
              ),
              icon: const Icon(Icons.manage_search_rounded, size: 20),
              label: const Text('Analyze URL'),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildSecurityFeaturesCard() {
    final textTheme = Theme.of(context).textTheme;
    final palette = context.qrPalette;
    final features = [
      _SecurityFeature(
        icon: Icons.manage_search_rounded,
        color: AppColors.primaryBlueBright,
        title: 'Instant Analysis',
        description: 'Real-time threat detection',
      ),
      _SecurityFeature(
        icon: Icons.lock_outline_rounded,
        color: AppColors.safe,
        title: 'Stay Protected',
        description: 'Risky links are analyzed before you visit',
      ),
      _SecurityFeature(
        icon: Icons.visibility_outlined,
        color: AppColors.medium,
        title: 'Stay Informed',
        description: 'See what is safe before opening a link',
      ),
    ];

    return CyberCard(
      accentColor: AppColors.primaryBlue,
      padding: const EdgeInsets.all(AppSpacing.lg),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            'Security at your fingertips',
            style: textTheme.titleMedium?.copyWith(
              color: palette.textPrimary,
              fontWeight: FontWeight.w700,
            ),
          ),
          const SizedBox(height: AppSpacing.lg),
          LayoutBuilder(
            builder: (context, constraints) {
              if (constraints.maxWidth >= 660) {
                return Row(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Expanded(child: features[0]),
                    const SizedBox(width: AppSpacing.md),
                    Expanded(child: features[1]),
                    const SizedBox(width: AppSpacing.md),
                    Expanded(child: features[2]),
                  ],
                );
              }

              return Column(
                children: [
                  features[0],
                  const SizedBox(height: AppSpacing.sm),
                  features[1],
                  const SizedBox(height: AppSpacing.sm),
                  features[2],
                ],
              );
            },
          ),
        ],
      ),
    );
  }

  Widget _buildAnalysisFailureOverlay() {
    final textTheme = Theme.of(context).textTheme;
    final palette = context.qrPalette;
    final retryUrl = failedUrl;

    return Positioned.fill(
      child: ColoredBox(
        color: palette.background.withValues(alpha: 0.94),
        child: Center(
          child: Padding(
            padding: const EdgeInsets.all(AppSpacing.xl),
            child: ConstrainedBox(
              constraints: const BoxConstraints(maxWidth: 360),
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
                      size: 42,
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
                    SizedBox(
                      width: double.infinity,
                      child: ElevatedButton.icon(
                        onPressed: retryUrl == null
                            ? null
                            : () => analyzeUrl(retryUrl),
                        icon: const Icon(Icons.refresh_rounded),
                        label: const Text('Retry'),
                      ),
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

  Widget _buildLoadingOverlay() {
    final textTheme = Theme.of(context).textTheme;
    final palette = context.qrPalette;

    return Positioned.fill(
      child: ColoredBox(
        color: palette.background.withValues(alpha: 0.86),
        child: Center(
          child: Padding(
            padding: const EdgeInsets.all(AppSpacing.xl),
            child: ConstrainedBox(
              constraints: const BoxConstraints(maxWidth: 340),
              child: CyberCard(
                accentColor: AppColors.primaryBlue,
                borderColor: palette.borderBright,
                padding: const EdgeInsets.all(AppSpacing.xl),
                child: Column(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    Container(
                      width: 52,
                      height: 52,
                      decoration: BoxDecoration(
                        color: palette.primaryBlueSoft,
                        shape: BoxShape.circle,
                        border: Border.all(
                          color: AppColors.primaryBlue.withValues(alpha: 0.30),
                        ),
                      ),
                      alignment: Alignment.center,
                      child: const SizedBox(
                        width: 26,
                        height: 26,
                        child: CircularProgressIndicator(strokeWidth: 2.5),
                      ),
                    ),
                    const SizedBox(height: AppSpacing.lg),
                    Text(
                      'Analyzing destination...',
                      textAlign: TextAlign.center,
                      style: textTheme.titleMedium?.copyWith(
                        color: palette.textPrimary,
                        fontWeight: FontWeight.w700,
                      ),
                    ),
                    const SizedBox(height: AppSpacing.sm),
                    Text(
                      'QRShield is checking this link in an isolated environment',
                      textAlign: TextAlign.center,
                      style: textTheme.bodySmall?.copyWith(
                        color: palette.textSecondary,
                        height: 1.45,
                      ),
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
}

class _SecurityFeature extends StatelessWidget {
  final IconData icon;
  final Color color;
  final String title;
  final String description;

  const _SecurityFeature({
    required this.icon,
    required this.color,
    required this.title,
    required this.description,
  });

  @override
  Widget build(BuildContext context) {
    final textTheme = Theme.of(context).textTheme;
    final palette = context.qrPalette;

    return Container(
      padding: const EdgeInsets.all(AppSpacing.md),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.07),
        borderRadius: BorderRadius.circular(AppSpacing.radiusMedium),
        border: Border.all(color: color.withValues(alpha: 0.20)),
      ),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Container(
            width: 34,
            height: 34,
            decoration: BoxDecoration(
              color: color.withValues(alpha: 0.14),
              borderRadius: BorderRadius.circular(AppSpacing.radiusSmall),
            ),
            alignment: Alignment.center,
            child: Icon(icon, color: color, size: 18),
          ),
          const SizedBox(width: AppSpacing.sm),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              mainAxisSize: MainAxisSize.min,
              children: [
                Text(
                  title,
                  style: textTheme.labelLarge?.copyWith(
                    color: palette.textPrimary,
                    fontWeight: FontWeight.w700,
                  ),
                ),
                const SizedBox(height: 2),
                Text(
                  description,
                  style: textTheme.bodySmall?.copyWith(
                    color: palette.textSecondary,
                    height: 1.35,
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
