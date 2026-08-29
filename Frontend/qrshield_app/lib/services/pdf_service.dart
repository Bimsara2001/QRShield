import 'package:flutter/services.dart';
import 'package:pdf/pdf.dart';
import 'package:pdf/widgets.dart' as pw;
import 'package:printing/printing.dart';

/// Builds the branded, printable QRShield security report.
///
/// The export entry point and all result-map fields are intentionally kept
/// unchanged. This service only transforms the supplied analysis result into a
/// clearer PDF presentation.
class PdfService {
  static final PdfColor _navy = PdfColor.fromInt(0xFF07101F);
  static final PdfColor _navySoft = PdfColor.fromInt(0xFF10213A);
  static final PdfColor _primary = PdfColor.fromInt(0xFF2F9BFF);
  static final PdfColor _primaryBright = PdfColor.fromInt(0xFF46B5FF);
  static final PdfColor _blueSoft = PdfColor.fromInt(0xFFEEF6FF);
  static final PdfColor _surface = PdfColors.white;
  static final PdfColor _surfaceSoft = PdfColor.fromInt(0xFFF6F9FD);
  static final PdfColor _border = PdfColor.fromInt(0xFFD8E2EE);
  static final PdfColor _textPrimary = PdfColor.fromInt(0xFF15243A);
  static final PdfColor _textSecondary = PdfColor.fromInt(0xFF617087);
  static final PdfColor _safe = PdfColor.fromInt(0xFF249E4D);
  static final PdfColor _safeSoft = PdfColor.fromInt(0xFFEAF8EE);
  static final PdfColor _medium = PdfColor.fromInt(0xFFD98200);
  static final PdfColor _mediumSoft = PdfColor.fromInt(0xFFFFF3DF);
  static final PdfColor _danger = PdfColor.fromInt(0xFFD9363E);
  static final PdfColor _dangerSoft = PdfColor.fromInt(0xFFFFECEE);

  static Future<void> generateScanReport(
    Map<String, dynamic> result,
  ) async {
    final pdf = pw.Document();
    final generatedAt = DateTime.now();
    final generatedLabel = _formatTimestamp(generatedAt);
    final logo = await _loadLogo();

    final verdict = _readText(result['verdict']);
    final riskScore = _readText(result['risk_score']);
    final reasons = _readReasons(result['reasons']);
    final virusTotal = _readMap(result['virustotal']);
    final virusTotalStatus = _readText(virusTotal['status']);
    final virusTotalUnavailable =
        virusTotal.isEmpty || virusTotalStatus?.toLowerCase() == 'error';
    final virusTotalVerdict = virusTotalUnavailable
        ? null
        : _readText(virusTotal['verdict']);
    final virusTotalMetrics = virusTotalUnavailable
        ? const <_ThreatMetric>[]
        : _readVirusTotalMetrics(virusTotal);

    final urlDetails = <_DetailField>[
      if (_readText(result['original_url']) case final originalUrl?)
        _DetailField('Original URL', originalUrl),
      if (_readText(result['final_url']) case final finalUrl?)
        _DetailField('Final URL', finalUrl),
      if (_readText(result['title']) case final title?)
        _DetailField('Page Title', title),
    ];

    pdf.addPage(
      pw.MultiPage(
        pageFormat: PdfPageFormat.a4,
        margin: const pw.EdgeInsets.fromLTRB(36, 34, 36, 42),
        footer: (context) => _buildFooter(
          context,
          generatedLabel: generatedLabel,
        ),
        build: (context) {
          return [
            _buildHeader(
              generatedLabel: generatedLabel,
              logo: logo,
            ),
            pw.SizedBox(height: 22),
            if (verdict != null || riskScore != null || virusTotalVerdict != null)
              _buildSummary(
                verdict: verdict,
                riskScore: riskScore,
                virusTotalVerdict: virusTotalVerdict,
              ),
            if (verdict != null || riskScore != null || virusTotalVerdict != null)
              pw.SizedBox(height: 22),
            if (urlDetails.isNotEmpty) ...[
              _buildSectionTitle('URL Details'),
              pw.SizedBox(height: 9),
              _buildUrlDetails(urlDetails),
              pw.SizedBox(height: 20),
            ],
            _buildSectionTitle('VirusTotal Intelligence'),
            pw.SizedBox(height: 9),
            _buildThreatIntelligence(
              metrics: virusTotalMetrics,
              verdict: virusTotalVerdict,
              unavailable: virusTotalUnavailable,
            ),
            pw.SizedBox(height: 20),
            _buildSectionTitle('Security Findings'),
            pw.SizedBox(height: 9),
            _buildFindings(
              reasons: reasons,
              verdict: verdict,
            ),
            if (_recommendationFor(verdict) case final recommendation?) ...[
              pw.SizedBox(height: 20),
              _buildSectionTitle('Recommendation'),
              pw.SizedBox(height: 9),
              _buildRecommendation(recommendation),
            ],
          ];
        },
      ),
    );

    await Printing.layoutPdf(
      name: 'QRShield_Scan_Report.pdf',
      onLayout: (format) async => pdf.save(),
    );
  }

  static Future<pw.MemoryImage?> _loadLogo() async {
    try {
      final assetData = await rootBundle.load('assets/images/Logo.png');
      return pw.MemoryImage(
        assetData.buffer.asUint8List(
          assetData.offsetInBytes,
          assetData.lengthInBytes,
        ),
      );
    } catch (_) {
      // A text-only header is still a complete report when the asset is not
      // available to a given platform or test environment.
      return null;
    }
  }

  static String? _readText(dynamic value) {
    if (value == null) return null;
    final text = value.toString().trim();
    return text.isEmpty ? null : text;
  }

  static Map<dynamic, dynamic> _readMap(dynamic value) {
    return value is Map ? value : const <dynamic, dynamic>{};
  }

  static List<String> _readReasons(dynamic value) {
    if (value is! Iterable) return const <String>[];

    return value
        .map(_readText)
        .whereType<String>()
        .toList(growable: false);
  }

  static List<_ThreatMetric> _readVirusTotalMetrics(
    Map<dynamic, dynamic> virusTotal,
  ) {
    final metricDefinitions = <_MetricDefinition>[
      _MetricDefinition('malicious', 'Malicious', _danger, _dangerSoft),
      _MetricDefinition('suspicious', 'Suspicious', _medium, _mediumSoft),
      _MetricDefinition('harmless', 'Harmless', _safe, _safeSoft),
      _MetricDefinition('undetected', 'Undetected', _primary, _blueSoft),
    ];

    return metricDefinitions
        .where((definition) => _readText(virusTotal[definition.key]) != null)
        .map(
          (definition) => _ThreatMetric(
            label: definition.label,
            value: _readText(virusTotal[definition.key])!,
            color: definition.color,
            backgroundColor: definition.backgroundColor,
          ),
        )
        .toList(growable: false);
  }

  static pw.Widget _buildHeader({
    required String generatedLabel,
    required pw.MemoryImage? logo,
  }) {
    return pw.Container(
      width: double.infinity,
      padding: const pw.EdgeInsets.all(20),
      decoration: pw.BoxDecoration(
        color: _navy,
        borderRadius: pw.BorderRadius.circular(16),
        border: pw.Border.all(color: _navySoft),
      ),
      child: pw.Row(
        crossAxisAlignment: pw.CrossAxisAlignment.center,
        children: [
          if (logo != null) ...[
            pw.Container(
              width: 48,
              height: 48,
              padding: const pw.EdgeInsets.all(3),
              decoration: pw.BoxDecoration(
                color: PdfColors.white,
                borderRadius: pw.BorderRadius.circular(12),
                border: pw.Border.all(color: _primaryBright),
              ),
              child: pw.Image(logo, fit: pw.BoxFit.contain),
            ),
            pw.SizedBox(width: 14),
          ],
          pw.Expanded(
            child: pw.Column(
              crossAxisAlignment: pw.CrossAxisAlignment.start,
              children: [
                pw.Container(
                  width: 46,
                  height: 3,
                  color: _primaryBright,
                ),
                pw.SizedBox(height: 9),
                pw.Text(
                  'QRShield Security Report',
                  style: pw.TextStyle(
                    color: PdfColors.white,
                    fontSize: 23,
                    fontWeight: pw.FontWeight.bold,
                  ),
                ),
                pw.SizedBox(height: 4),
                pw.Text(
                  'Advanced QR & URL Threat Analysis',
                  style: pw.TextStyle(
                    color: PdfColor.fromInt(0xFFC9D9EC),
                    fontSize: 10.5,
                  ),
                ),
              ],
            ),
          ),
          pw.SizedBox(width: 12),
          pw.Container(
            padding: const pw.EdgeInsets.symmetric(horizontal: 10, vertical: 7),
            decoration: pw.BoxDecoration(
              color: PdfColor.fromInt(0xFF132D4D),
              borderRadius: pw.BorderRadius.circular(10),
              border: pw.Border.all(color: PdfColor.fromInt(0xFF29547E)),
            ),
            child: pw.Column(
              crossAxisAlignment: pw.CrossAxisAlignment.end,
              children: [
                pw.Text(
                  'REPORT GENERATED',
                  style: pw.TextStyle(
                    color: _primaryBright,
                    fontSize: 6.5,
                    fontWeight: pw.FontWeight.bold,
                    letterSpacing: 0.7,
                  ),
                ),
                pw.SizedBox(height: 3),
                pw.Text(
                  generatedLabel,
                  style: const pw.TextStyle(
                    color: PdfColors.white,
                    fontSize: 8.5,
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  static pw.Widget _buildSummary({
    required String? verdict,
    required String? riskScore,
    required String? virusTotalVerdict,
  }) {
    final cards = <pw.Widget>[
      if (verdict != null)
        _buildSummaryCard(
          label: 'Verdict',
          value: verdict,
          color: _verdictColor(verdict),
          backgroundColor: _verdictBackground(verdict),
        ),
      if (riskScore != null)
        _buildSummaryCard(
          label: 'Risk Score',
          value: _scoreLabel(riskScore),
          color: _primary,
          backgroundColor: _blueSoft,
        ),
      if (virusTotalVerdict != null)
        _buildSummaryCard(
          label: 'VT Verdict',
          value: virusTotalVerdict,
          color: _primary,
          backgroundColor: _blueSoft,
        ),
    ];

    return pw.Row(
      crossAxisAlignment: pw.CrossAxisAlignment.start,
      children: [
        for (var index = 0; index < cards.length; index++) ...[
          if (index > 0) pw.SizedBox(width: 10),
          pw.Expanded(child: cards[index]),
        ],
      ],
    );
  }

  static pw.Widget _buildSummaryCard({
    required String label,
    required String value,
    required PdfColor color,
    required PdfColor backgroundColor,
  }) {
    return pw.Container(
      padding: const pw.EdgeInsets.all(13),
      decoration: pw.BoxDecoration(
        color: backgroundColor,
        borderRadius: pw.BorderRadius.circular(12),
        border: pw.Border.all(color: color, width: 0.8),
      ),
      child: pw.Column(
        crossAxisAlignment: pw.CrossAxisAlignment.start,
        mainAxisAlignment: pw.MainAxisAlignment.spaceBetween,
        children: [
          pw.Text(
            label.toUpperCase(),
            style: pw.TextStyle(
              color: _textSecondary,
              fontSize: 7.5,
              fontWeight: pw.FontWeight.bold,
              letterSpacing: 0.7,
            ),
          ),
          pw.SizedBox(height: 9),
          pw.Text(
            value,
            style: pw.TextStyle(
              color: color,
              fontSize: 16,
              fontWeight: pw.FontWeight.bold,
            ),
          ),
        ],
      ),
    );
  }

  static pw.Widget _buildSectionTitle(String title) {
    return pw.Row(
      children: [
        pw.Container(
          width: 4,
          height: 17,
          decoration: pw.BoxDecoration(
            color: _primary,
            borderRadius: pw.BorderRadius.circular(4),
          ),
        ),
        pw.SizedBox(width: 8),
        pw.Text(
          title,
          style: pw.TextStyle(
            color: _textPrimary,
            fontSize: 15,
            fontWeight: pw.FontWeight.bold,
          ),
        ),
      ],
    );
  }

  static pw.Widget _buildUrlDetails(List<_DetailField> details) {
    return pw.Container(
      padding: const pw.EdgeInsets.all(14),
      decoration: pw.BoxDecoration(
        color: _surface,
        borderRadius: pw.BorderRadius.circular(12),
        border: pw.Border.all(color: _border),
      ),
      child: pw.Column(
        crossAxisAlignment: pw.CrossAxisAlignment.start,
        children: [
          for (var index = 0; index < details.length; index++) ...[
            if (index > 0) _buildDivider(),
            pw.Padding(
              padding: pw.EdgeInsets.only(top: index == 0 ? 0 : 10),
              child: pw.Column(
                crossAxisAlignment: pw.CrossAxisAlignment.start,
                children: [
                  pw.Text(
                    details[index].label.toUpperCase(),
                    style: pw.TextStyle(
                      color: _primary,
                      fontSize: 7.5,
                      fontWeight: pw.FontWeight.bold,
                      letterSpacing: 0.65,
                    ),
                  ),
                  pw.SizedBox(height: 4),
                  pw.Text(
                    details[index].value,
                    style: pw.TextStyle(
                      color: _textPrimary,
                      fontSize: 9.5,
                    ),
                  ),
                ],
              ),
            ),
          ],
        ],
      ),
    );
  }

  static pw.Widget _buildThreatIntelligence({
    required List<_ThreatMetric> metrics,
    required String? verdict,
    required bool unavailable,
  }) {
    if (unavailable || (metrics.isEmpty && verdict == null)) {
      return _buildNeutralState(
        title: 'Threat intelligence unavailable',
        message: 'VirusTotal analysis was not available for this report.',
      );
    }

    return pw.Container(
      padding: const pw.EdgeInsets.all(14),
      decoration: pw.BoxDecoration(
        color: _surface,
        borderRadius: pw.BorderRadius.circular(12),
        border: pw.Border.all(color: _border),
      ),
      child: pw.Column(
        crossAxisAlignment: pw.CrossAxisAlignment.start,
        children: [
          if (metrics.isNotEmpty)
            pw.Wrap(
              spacing: 10,
              runSpacing: 10,
              children: metrics
                  .map(
                    (metric) => pw.Container(
                      width: 112,
                      padding: const pw.EdgeInsets.all(10),
                      decoration: pw.BoxDecoration(
                        color: metric.backgroundColor,
                        borderRadius: pw.BorderRadius.circular(10),
                        border: pw.Border.all(color: metric.color, width: 0.7),
                      ),
                      child: pw.Column(
                        crossAxisAlignment: pw.CrossAxisAlignment.start,
                        children: [
                          pw.Text(
                            metric.label.toUpperCase(),
                            style: pw.TextStyle(
                              color: _textSecondary,
                              fontSize: 6.8,
                              fontWeight: pw.FontWeight.bold,
                              letterSpacing: 0.55,
                            ),
                          ),
                          pw.SizedBox(height: 6),
                          pw.Text(
                            metric.value,
                            style: pw.TextStyle(
                              color: metric.color,
                              fontSize: 16,
                              fontWeight: pw.FontWeight.bold,
                            ),
                          ),
                        ],
                      ),
                    ),
                  )
                  .toList(growable: false),
            ),
          if (metrics.isNotEmpty && verdict != null)
            pw.SizedBox(height: 11),
          if (verdict != null)
            pw.Container(
              width: double.infinity,
              padding: const pw.EdgeInsets.symmetric(horizontal: 10, vertical: 8),
              decoration: pw.BoxDecoration(
                color: _blueSoft,
                borderRadius: pw.BorderRadius.circular(9),
                border: pw.Border.all(color: _primary, width: 0.7),
              ),
              child: pw.Row(
                children: [
                  pw.Container(
                    width: 7,
                    height: 7,
                    decoration: pw.BoxDecoration(
                      color: _primary,
                      shape: pw.BoxShape.circle,
                    ),
                  ),
                  pw.SizedBox(width: 7),
                  pw.Expanded(
                    child: pw.Text(
                      'VirusTotal verdict',
                      style: pw.TextStyle(
                        color: _textSecondary,
                        fontSize: 8.5,
                        fontWeight: pw.FontWeight.bold,
                      ),
                    ),
                  ),
                  pw.SizedBox(width: 8),
                  pw.Expanded(
                    child: pw.Text(
                      verdict,
                      textAlign: pw.TextAlign.right,
                      style: pw.TextStyle(
                        color: _textPrimary,
                        fontSize: 9,
                        fontWeight: pw.FontWeight.bold,
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

  static pw.Widget _buildFindings({
    required List<String> reasons,
    required String? verdict,
  }) {
    if (reasons.isEmpty) {
      return pw.Container(
        padding: const pw.EdgeInsets.all(13),
        decoration: pw.BoxDecoration(
          color: _safeSoft,
          borderRadius: pw.BorderRadius.circular(12),
          border: pw.Border.all(color: _safe, width: 0.8),
        ),
        child: pw.Row(
          crossAxisAlignment: pw.CrossAxisAlignment.start,
          children: [
            pw.Container(
              width: 18,
              height: 18,
              decoration: pw.BoxDecoration(
                color: _safe,
                shape: pw.BoxShape.circle,
              ),
              alignment: pw.Alignment.center,
              child: pw.Text(
                'OK',
                style: pw.TextStyle(
                  color: PdfColors.white,
                  fontSize: 5.5,
                ),
              ),
            ),
            pw.SizedBox(width: 9),
            pw.Expanded(
              child: pw.Text(
                'No major threat indicators detected',
                style: pw.TextStyle(
                  color: _safe,
                  fontSize: 10,
                  fontWeight: pw.FontWeight.bold,
                ),
              ),
            ),
          ],
        ),
      );
    }

    final accent = verdict == null ? _medium : _verdictColor(verdict);
    final background =
        verdict == null ? _mediumSoft : _verdictBackground(verdict);

    return pw.Column(
      crossAxisAlignment: pw.CrossAxisAlignment.stretch,
      children: reasons
          .map(
            (reason) => pw.Container(
              margin: const pw.EdgeInsets.only(bottom: 8),
              padding: const pw.EdgeInsets.all(11),
              decoration: pw.BoxDecoration(
                color: background,
                borderRadius: pw.BorderRadius.circular(10),
                border: pw.Border.all(color: accent, width: 0.7),
              ),
              child: pw.Row(
                crossAxisAlignment: pw.CrossAxisAlignment.start,
                children: [
                  pw.Container(
                    width: 8,
                    height: 8,
                    margin: const pw.EdgeInsets.only(top: 2),
                    decoration: pw.BoxDecoration(
                      color: accent,
                      shape: pw.BoxShape.circle,
                    ),
                  ),
                  pw.SizedBox(width: 8),
                  pw.Expanded(
                    child: pw.Text(
                      reason,
                      style: pw.TextStyle(
                        color: _textPrimary,
                        fontSize: 9.5,
                      ),
                    ),
                  ),
                ],
              ),
            ),
          )
          .toList(growable: false),
    );
  }

  static pw.Widget _buildRecommendation(_Recommendation recommendation) {
    return pw.Container(
      padding: const pw.EdgeInsets.all(14),
      decoration: pw.BoxDecoration(
        color: recommendation.backgroundColor,
        borderRadius: pw.BorderRadius.circular(12),
        border: pw.Border.all(color: recommendation.color, width: 0.9),
      ),
      child: pw.Row(
        crossAxisAlignment: pw.CrossAxisAlignment.start,
        children: [
          pw.Container(
            width: 4,
            height: 32,
            decoration: pw.BoxDecoration(
              color: recommendation.color,
              borderRadius: pw.BorderRadius.circular(4),
            ),
          ),
          pw.SizedBox(width: 10),
          pw.Expanded(
            child: pw.Text(
              recommendation.message,
              style: pw.TextStyle(
                color: _textPrimary,
                fontSize: 10,
                fontWeight: pw.FontWeight.bold,
              ),
            ),
          ),
        ],
      ),
    );
  }

  static pw.Widget _buildNeutralState({
    required String title,
    required String message,
  }) {
    return pw.Container(
      padding: const pw.EdgeInsets.all(13),
      decoration: pw.BoxDecoration(
        color: _surfaceSoft,
        borderRadius: pw.BorderRadius.circular(12),
        border: pw.Border.all(color: _border),
      ),
      child: pw.Row(
        crossAxisAlignment: pw.CrossAxisAlignment.start,
        children: [
          pw.Container(
            width: 18,
            height: 18,
            decoration: pw.BoxDecoration(
              color: _blueSoft,
              shape: pw.BoxShape.circle,
              border: pw.Border.all(color: _primary),
            ),
          ),
          pw.SizedBox(width: 9),
          pw.Expanded(
            child: pw.Column(
              crossAxisAlignment: pw.CrossAxisAlignment.start,
              children: [
                pw.Text(
                  title,
                  style: pw.TextStyle(
                    color: _textPrimary,
                    fontSize: 10,
                    fontWeight: pw.FontWeight.bold,
                  ),
                ),
                pw.SizedBox(height: 3),
                pw.Text(
                  message,
                  style: pw.TextStyle(
                    color: _textSecondary,
                    fontSize: 8.8,
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  static pw.Widget _buildDivider() {
    return pw.Container(
      margin: const pw.EdgeInsets.only(top: 10),
      height: 0.7,
      color: _border,
    );
  }

  static pw.Widget _buildFooter(
    pw.Context context, {
    required String generatedLabel,
  }) {
    return pw.Container(
      margin: const pw.EdgeInsets.only(top: 16),
      padding: const pw.EdgeInsets.only(top: 8),
      decoration: pw.BoxDecoration(
        border: pw.Border(top: pw.BorderSide(color: _border, width: 0.7)),
      ),
      child: pw.Row(
        children: [
          pw.Expanded(
            child: pw.Text(
              'Generated by QRShield | QR Code Threat Detection Platform',
              style: pw.TextStyle(
                color: _textSecondary,
                fontSize: 7.3,
              ),
            ),
          ),
          pw.SizedBox(width: 10),
          pw.Text(
            '$generatedLabel | Page ${context.pageNumber} of ${context.pagesCount}',
            style: pw.TextStyle(
              color: _textSecondary,
              fontSize: 7.3,
            ),
          ),
        ],
      ),
    );
  }

  static String _scoreLabel(String score) {
    return score.contains('/') ? score : '$score / 100';
  }

  static PdfColor _verdictColor(String? verdict) {
    final normalized = verdict?.toLowerCase() ?? '';
    if (normalized.contains('low') || normalized.contains('safe')) {
      return _safe;
    }
    if (normalized.contains('medium') || normalized.contains('suspicious')) {
      return _medium;
    }
    if (normalized.contains('high') || normalized.contains('danger')) {
      return _danger;
    }
    return _primary;
  }

  static PdfColor _verdictBackground(String? verdict) {
    final normalized = verdict?.toLowerCase() ?? '';
    if (normalized.contains('low') || normalized.contains('safe')) {
      return _safeSoft;
    }
    if (normalized.contains('medium') || normalized.contains('suspicious')) {
      return _mediumSoft;
    }
    if (normalized.contains('high') || normalized.contains('danger')) {
      return _dangerSoft;
    }
    return _blueSoft;
  }

  static _Recommendation? _recommendationFor(String? verdict) {
    switch (verdict) {
      case 'Low Risk':
        return _Recommendation(
          color: _safe,
          backgroundColor: _safeSoft,
          message:
              'No major phishing indicators were detected. Proceed with normal caution.',
        );
      case 'Medium Risk':
        return _Recommendation(
          color: _medium,
          backgroundColor: _mediumSoft,
          message:
              'Some suspicious indicators were detected. Review the destination carefully before opening.',
        );
      case 'High Risk':
        return _Recommendation(
          color: _danger,
          backgroundColor: _dangerSoft,
          message:
              'Multiple phishing indicators were detected. Avoid opening this destination.',
        );
      default:
        return null;
    }
  }

  static String _formatTimestamp(DateTime value) {
    const months = <String>[
      'Jan',
      'Feb',
      'Mar',
      'Apr',
      'May',
      'Jun',
      'Jul',
      'Aug',
      'Sep',
      'Oct',
      'Nov',
      'Dec',
    ];
    final hour = value.hour.toString().padLeft(2, '0');
    final minute = value.minute.toString().padLeft(2, '0');
    final second = value.second.toString().padLeft(2, '0');

    return '${value.day} ${months[value.month - 1]} ${value.year} $hour:$minute:$second';
  }
}

class _DetailField {
  final String label;
  final String value;

  const _DetailField(this.label, this.value);
}

class _MetricDefinition {
  final String key;
  final String label;
  final PdfColor color;
  final PdfColor backgroundColor;

  const _MetricDefinition(
    this.key,
    this.label,
    this.color,
    this.backgroundColor,
  );
}

class _ThreatMetric {
  final String label;
  final String value;
  final PdfColor color;
  final PdfColor backgroundColor;

  const _ThreatMetric({
    required this.label,
    required this.value,
    required this.color,
    required this.backgroundColor,
  });
}

class _Recommendation {
  final PdfColor color;
  final PdfColor backgroundColor;
  final String message;

  const _Recommendation({
    required this.color,
    required this.backgroundColor,
    required this.message,
  });
}
