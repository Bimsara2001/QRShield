import 'package:flutter/material.dart';
import 'package:mobile_scanner/mobile_scanner.dart';

import '../services/api_service.dart';
import 'result_screen.dart';

class ScanScreen extends StatefulWidget {
  const ScanScreen({super.key});

  @override
  State<ScanScreen> createState() =>
      _ScanScreenState();
}

class _ScanScreenState extends State<ScanScreen> {
  bool scanned = false;
  bool loading = false;

  final TextEditingController urlController =
      TextEditingController();

  Future<void> analyzeUrl(String url) async {
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
    });

    try {
      final result =
          await ApiService.scanUrl(url.trim());

      if (!mounted) return;

      setState(() {
        loading = false;
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
    } catch (e) {
      if (!mounted) return;

      setState(() {
        loading = false;
      });

      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text("Error: $e"),
        ),
      );

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
    return Scaffold(
      backgroundColor: const Color(0xFF050B18),

      appBar: AppBar(
        backgroundColor: const Color(0xFF050B18),
        elevation: 0,
        title: const Text(
          "QR Scanner",
          style: TextStyle(
            color: Colors.white,
            fontWeight: FontWeight.bold,
          ),
        ),
      ),

      body: Stack(
        children: [
          MobileScanner(
            controller: MobileScannerController(
              formats: [
                BarcodeFormat.qrCode,
              ],
              detectionSpeed:
                  DetectionSpeed.noDuplicates,
            ),

            onDetect: (capture) async {
              if (scanned) return;

              if (capture.barcodes.isEmpty) {
                return;
              }

              final barcode =
                  capture.barcodes.first;

              final url =
                  barcode.rawValue ?? "";

              if (url.isEmpty) {
                return;
              }

              scanned = true;

              await analyzeUrl(url);
            },
          ),

          Center(
            child: Container(
              width: 260,
              height: 260,
              decoration: BoxDecoration(
                border: Border.all(
                  color: Colors.lightBlueAccent,
                  width: 3,
                ),
                borderRadius:
                    BorderRadius.circular(20),
              ),
            ),
          ),

          Positioned(
            top: 40,
            left: 20,
            right: 20,
            child: Column(
              children: const [
                Text(
                  "Scan Any QR Code",
                  style: TextStyle(
                    color: Colors.white,
                    fontSize: 24,
                    fontWeight:
                        FontWeight.bold,
                  ),
                ),
                SizedBox(height: 10),
                Text(
                  "Or manually enter a URL below",
                  textAlign: TextAlign.center,
                  style: TextStyle(
                    color: Colors.white70,
                  ),
                ),
              ],
            ),
          ),

          Positioned(
            left: 20,
            right: 20,
            bottom: 30,
            child: Container(
              padding: const EdgeInsets.all(16),
              decoration: BoxDecoration(
                color: const Color(0xFF0B1220),
                borderRadius:
                    BorderRadius.circular(16),
              ),
              child: Column(
                children: [
                  TextField(
                    controller: urlController,
                    style: const TextStyle(
                      color: Colors.white,
                    ),
                    decoration: InputDecoration(
                      hintText: "Enter URL manually",
                      hintStyle: const TextStyle(
                        color: Colors.white54,
                      ),
                      prefixIcon: const Icon(
                        Icons.link,
                        color: Colors.white54,
                      ),
                      filled: true,
                      fillColor:
                          const Color(0xFF050B18),
                      border: OutlineInputBorder(
                        borderRadius:
                            BorderRadius.circular(12),
                        borderSide: BorderSide.none,
                      ),
                    ),
                  ),

                  const SizedBox(height: 12),

                  SizedBox(
                    width: double.infinity,
                    child: ElevatedButton.icon(
                      onPressed: () {
                        analyzeUrl(
                          urlController.text,
                        );
                      },
                      icon: const Icon(Icons.search),
                      label: const Text(
                        "Analyze URL",
                      ),
                    ),
                  ),
                ],
              ),
            ),
          ),

          if (loading)
            Container(
              color: Colors.black54,
              child: const Center(
                child: Column(
                  mainAxisAlignment:
                      MainAxisAlignment.center,
                  children: [
                    CircularProgressIndicator(),
                    SizedBox(height: 20),
                    Text(
                      "Analyzing URL...",
                      style: TextStyle(
                        color: Colors.white,
                        fontSize: 18,
                      ),
                    )
                  ],
                ),
              ),
            ),
        ],
      ),
    );
  }
}