import 'package:pdf/pdf.dart';
import 'package:pdf/widgets.dart' as pw;
import 'package:printing/printing.dart';

class PdfService {
  static Future<void> generateScanReport(
    Map<String, dynamic> result,
  ) async {
    final pdf = pw.Document();

    final verdict = result["verdict"] ?? "Unknown";
    final riskScore = result["risk_score"] ?? "-";
    final reasons = result["reasons"] ?? [];
    final vt = result["virustotal"] ?? {};

    PdfColor verdictColor() {
      if (verdict == "Low Risk") return PdfColors.green;
      if (verdict == "Medium Risk") return PdfColors.orange;
      return PdfColors.red;
    }

    pdf.addPage(
      pw.MultiPage(
        pageFormat: PdfPageFormat.a4,
        margin: const pw.EdgeInsets.all(32),

        build: (context) {
          return [
            // Header
            pw.Container(
              width: double.infinity,
              padding: const pw.EdgeInsets.all(18),
              decoration: pw.BoxDecoration(
                color: PdfColors.blueGrey900,
                borderRadius: pw.BorderRadius.circular(10),
              ),
              child: pw.Column(
                crossAxisAlignment: pw.CrossAxisAlignment.start,
                children: [
                  pw.Text(
                    "QRShield Security Report",
                    style: pw.TextStyle(
                      color: PdfColors.white,
                      fontSize: 26,
                      fontWeight: pw.FontWeight.bold,
                    ),
                  ),
                  pw.SizedBox(height: 6),
                  pw.Text(
                    "Advanced QR & URL Threat Analysis",
                    style: const pw.TextStyle(
                      color: PdfColors.grey300,
                      fontSize: 12,
                    ),
                  ),
                ],
              ),
            ),

            pw.SizedBox(height: 24),

            // Summary
            pw.Row(
              children: [
                pw.Expanded(
                  child: pw.Container(
                    padding: const pw.EdgeInsets.all(16),
                    decoration: pw.BoxDecoration(
                      border: pw.Border.all(
                        color: verdictColor(),
                        width: 2,
                      ),
                      borderRadius: pw.BorderRadius.circular(10),
                    ),
                    child: pw.Column(
                      crossAxisAlignment: pw.CrossAxisAlignment.start,
                      children: [
                        pw.Text(
                          "Verdict",
                          style: const pw.TextStyle(
                            color: PdfColors.grey700,
                            fontSize: 12,
                          ),
                        ),
                        pw.SizedBox(height: 6),
                        pw.Text(
                          verdict,
                          style: pw.TextStyle(
                            color: verdictColor(),
                            fontSize: 24,
                            fontWeight: pw.FontWeight.bold,
                          ),
                        ),
                      ],
                    ),
                  ),
                ),

                pw.SizedBox(width: 16),

                pw.Expanded(
                  child: pw.Container(
                    padding: const pw.EdgeInsets.all(16),
                    decoration: pw.BoxDecoration(
                      color: PdfColors.grey200,
                      borderRadius: pw.BorderRadius.circular(10),
                    ),
                    child: pw.Column(
                      crossAxisAlignment: pw.CrossAxisAlignment.start,
                      children: [
                        pw.Text(
                          "Risk Score",
                          style: const pw.TextStyle(
                            color: PdfColors.grey700,
                            fontSize: 12,
                          ),
                        ),
                        pw.SizedBox(height: 6),
                        pw.Text(
                          riskScore.toString(),
                          style: pw.TextStyle(
                            fontSize: 24,
                            fontWeight: pw.FontWeight.bold,
                          ),
                        ),
                      ],
                    ),
                  ),
                ),
              ],
            ),

            pw.SizedBox(height: 24),

            _sectionTitle("URL Details"),

            _table([
              ["Original URL", result["original_url"] ?? "Unknown"],
              ["Final URL", result["final_url"] ?? "Unknown"],
              ["Page Title", result["title"] ?? "Unknown"],
            ]),

            pw.SizedBox(height: 20),

            _sectionTitle("VirusTotal Intelligence"),

            _table([
              ["Malicious", "${vt["malicious"] ?? 0}"],
              ["Suspicious", "${vt["suspicious"] ?? 0}"],
              ["Harmless", "${vt["harmless"] ?? 0}"],
              ["VT Verdict", vt["verdict"] ?? "Unknown"],
            ]),

            pw.SizedBox(height: 20),

            _sectionTitle("Threat Reasons"),

            if (reasons.isEmpty)
              pw.Container(
                padding: const pw.EdgeInsets.all(12),
                decoration: pw.BoxDecoration(
                  color: PdfColors.green50,
                  borderRadius: pw.BorderRadius.circular(8),
                ),
                child: pw.Text(
                  "No threat indicators detected.",
                  style: const pw.TextStyle(
                    color: PdfColors.green800,
                  ),
                ),
              )
            else
              pw.Container(
                padding: const pw.EdgeInsets.all(12),
                decoration: pw.BoxDecoration(
                  color: PdfColors.orange50,
                  borderRadius: pw.BorderRadius.circular(8),
                ),
                child: pw.Column(
                  crossAxisAlignment: pw.CrossAxisAlignment.start,
                  children: reasons.map<pw.Widget>((reason) {
                    return pw.Padding(
                      padding: const pw.EdgeInsets.only(bottom: 6),
                      child: pw.Text(
                        "• ${reason.toString()}",
                        style: const pw.TextStyle(
                          fontSize: 11,
                          color: PdfColors.black,
                        ),
                      ),
                    );
                  }).toList(),
                ),
              ),

            pw.SizedBox(height: 30),

            pw.Divider(),

            pw.Text(
              "Generated by QRShield | AI-powered QR Code Threat Detection Platform",
              style: const pw.TextStyle(
                fontSize: 10,
                color: PdfColors.grey600,
              ),
            ),

            pw.Text(
              "Report generated: ${DateTime.now()}",
              style: const pw.TextStyle(
                fontSize: 10,
                color: PdfColors.grey600,
              ),
            ),
          ];
        },
      ),
    );

    await Printing.layoutPdf(
      name: "QRShield_Scan_Report.pdf",
      onLayout: (format) async => pdf.save(),
    );
  }

  static pw.Widget _sectionTitle(String title) {
    return pw.Padding(
      padding: const pw.EdgeInsets.only(bottom: 8),
      child: pw.Text(
        title,
        style: pw.TextStyle(
          fontSize: 18,
          fontWeight: pw.FontWeight.bold,
          color: PdfColors.blueGrey900,
        ),
      ),
    );
  }

  static pw.Widget _table(List<List<String>> rows) {
    return pw.Table(
      border: pw.TableBorder.all(
        color: PdfColors.grey400,
        width: 0.5,
      ),
      columnWidths: {
        0: const pw.FlexColumnWidth(1.3),
        1: const pw.FlexColumnWidth(3),
      },
      children: rows.map((row) {
        return pw.TableRow(
          children: [
            pw.Container(
              padding: const pw.EdgeInsets.all(8),
              color: PdfColors.grey200,
              child: pw.Text(
                row[0],
                style: pw.TextStyle(
                  fontWeight: pw.FontWeight.bold,
                ),
              ),
            ),
            pw.Container(
              padding: const pw.EdgeInsets.all(8),
              child: pw.Text(
                row[1],
                style: const pw.TextStyle(
                  fontSize: 10,
                ),
              ),
            ),
          ],
        );
      }).toList(),
    );
  }
}