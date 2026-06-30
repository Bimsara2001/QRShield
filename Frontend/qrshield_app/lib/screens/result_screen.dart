import 'package:flutter/material.dart';
import '../services/pdf_service.dart';

class ResultScreen extends StatelessWidget {
  final Map<String, dynamic> result;

  const ResultScreen({
    super.key,
    required this.result,
  });

  Color getVerdictColor(String verdict) {
    if (verdict == "Low Risk") return Colors.green;
    if (verdict == "Medium Risk") return Colors.orange;
    return Colors.red;
  }

  @override
  Widget build(BuildContext context) {
    final verdict =
        result["verdict"] ?? "Unknown";

    final reasons =
        result["reasons"] ?? [];

    final vt =
        result["virustotal"] ?? {};

    return Scaffold(
      backgroundColor: const Color(0xFF050B18),

      appBar: AppBar(
        backgroundColor: const Color(0xFF050B18),
        elevation: 0,
        title: const Text(
          "Scan Result",
          style: TextStyle(
            color: Colors.white,
          ),
        ),
      ),

      body: SingleChildScrollView(
        padding: const EdgeInsets.all(20),

        child: Column(
          crossAxisAlignment:
              CrossAxisAlignment.start,

          children: [
            ClipRRect(
              borderRadius:
                  BorderRadius.circular(20),

              child: Image.network(
                result["screenshot"] ?? "",
                errorBuilder:
                    (context, error, stackTrace) {
                  return Container(
                    height: 180,
                    color:
                        const Color(0xFF0B1220),

                    child: const Center(
                      child: Icon(
                        Icons.image_not_supported,
                        color: Colors.white70,
                        size: 50,
                      ),
                    ),
                  );
                },
              ),
            ),

            const SizedBox(height: 20),

            Container(
              width: double.infinity,
              padding:
                  const EdgeInsets.all(20),

              decoration: BoxDecoration(
                color:
                    const Color(0xFF0B1220),

                borderRadius:
                    BorderRadius.circular(16),
              ),

              child: Column(
                crossAxisAlignment:
                    CrossAxisAlignment.start,

                children: [
                  Chip(
                    backgroundColor:
                        getVerdictColor(
                      verdict,
                    ),

                    label: Text(
                      verdict,
                      style:
                          const TextStyle(
                        color: Colors.white,
                        fontWeight:
                            FontWeight.bold,
                      ),
                    ),
                  ),

                  const SizedBox(height: 12),

                  Text(
                    "Risk Score: ${result["risk_score"] ?? "-"}",
                    style:
                        const TextStyle(
                      color: Colors.white,
                      fontSize: 22,
                      fontWeight:
                          FontWeight.bold,
                    ),
                  ),
                ],
              ),
            ),

            const SizedBox(height: 20),

            _infoCard(
              title: "URL Details",
              children: [
                _infoText(
                  "Original URL",
                  result["original_url"] ??
                      "Unknown",
                ),

                _infoText(
                  "Final URL",
                  result["final_url"] ??
                      "Unknown",
                ),

                _infoText(
                  "Page Title",
                  result["title"] ??
                      "Unknown",
                ),
              ],
            ),

            const SizedBox(height: 20),

            _infoCard(
              title: "VirusTotal",
              children: [
                _infoText(
                  "Malicious",
                  "${vt["malicious"] ?? 0}",
                ),

                _infoText(
                  "Suspicious",
                  "${vt["suspicious"] ?? 0}",
                ),

                _infoText(
                  "Harmless",
                  "${vt["harmless"] ?? 0}",
                ),

                _infoText(
                  "Verdict",
                  vt["verdict"] ??
                      "Unknown",
                ),
              ],
            ),

            const SizedBox(height: 20),

            _infoCard(
              title: "Threat Reasons",
              children: reasons.isEmpty
                  ? [
                      const Text(
                        "No threat reasons found.",
                        style: TextStyle(
                          color:
                              Colors.white70,
                        ),
                      ),
                    ]
                  : reasons
                      .map<Widget>(
                        (reason) {
                          return Padding(
                            padding:
                                const EdgeInsets.only(
                              bottom: 8,
                            ),
                            child: Row(
                              crossAxisAlignment:
                                  CrossAxisAlignment
                                      .start,
                              children: [
                                const Icon(
                                  Icons.warning,
                                  color:
                                      Colors.orange,
                                  size: 20,
                                ),

                                const SizedBox(
                                    width: 8),

                                Expanded(
                                  child: Text(
                                    reason
                                        .toString(),
                                    style:
                                        const TextStyle(
                                      color: Colors
                                          .white70,
                                    ),
                                  ),
                                ),
                              ],
                            ),
                          );
                        },
                      )
                      .toList(),
            ),

            const SizedBox(height: 25),

            SizedBox(
              width: double.infinity,
              child: ElevatedButton.icon(
                onPressed: () async {
                  await PdfService
                      .generateScanReport(
                    result,
                  );
                },
                icon: const Icon(
                  Icons.picture_as_pdf,
                ),
                label: const Text(
                  "Export PDF Report",
                ),
              ),
            ),

            const SizedBox(height: 12),

            SizedBox(
              width: double.infinity,
              child: ElevatedButton.icon(
                onPressed: () {
                  Navigator.pop(
                    context,
                  );
                },
                icon:
                    const Icon(Icons.arrow_back),
                label: const Text(
                  "Back",
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _infoCard({
    required String title,
    required List<Widget> children,
  }) {
    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(20),

      decoration: BoxDecoration(
        color: const Color(0xFF0B1220),
        borderRadius:
            BorderRadius.circular(16),
      ),

      child: Column(
        crossAxisAlignment:
            CrossAxisAlignment.start,

        children: [
          Text(
            title,
            style: const TextStyle(
              color: Colors.white,
              fontSize: 20,
              fontWeight:
                  FontWeight.bold,
            ),
          ),

          const SizedBox(height: 15),

          ...children,
        ],
      ),
    );
  }

  Widget _infoText(
    String label,
    String value,
  ) {
    return Padding(
      padding:
          const EdgeInsets.only(bottom: 10),

      child: Column(
        crossAxisAlignment:
            CrossAxisAlignment.start,

        children: [
          Text(
            label,
            style: const TextStyle(
              color: Colors.white54,
              fontSize: 13,
            ),
          ),

          const SizedBox(height: 3),

          SelectableText(
            value,
            style: const TextStyle(
              color: Colors.white,
            ),
          ),
        ],
      ),
    );
  }
}