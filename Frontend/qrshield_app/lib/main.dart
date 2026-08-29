import 'dart:async';
import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:mobile_scanner/mobile_scanner.dart';
import 'package:http/http.dart' as http;
import 'services/api_service.dart';
import 'screens/main_navigation.dart';
import 'screens/splash_screen.dart';
import 'theme/app_theme.dart';
import 'theme/theme_controller.dart';

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  WidgetsBinding.instance.deferFirstFrame();
  runApp(const MyApp(releaseFirstFrameAfterThemeLoad: true));
}

class MyApp extends StatefulWidget {
  /// Only the real application entry point defers Flutter's first frame.
  /// Keeping this opt-in makes direct widget construction safe in tests.
  final bool releaseFirstFrameAfterThemeLoad;

  const MyApp({super.key, this.releaseFirstFrameAfterThemeLoad = false});

  @override
  State<MyApp> createState() => _MyAppState();
}

class _MyAppState extends State<MyApp> {
  late final ThemeController _themeController;
  bool _themeReady = false;
  bool _showSplash = true;

  @override
  void initState() {
    super.initState();
    _themeController = ThemeController();
    unawaited(_loadThemeBeforeFirstFrame());
  }

  Future<void> _loadThemeBeforeFirstFrame() async {
    await _themeController.load();

    if (!mounted) {
      _allowFirstFrame();
      return;
    }

    setState(() {
      _themeReady = true;
    });
    _allowFirstFrame();
  }

  void _allowFirstFrame() {
    if (widget.releaseFirstFrameAfterThemeLoad) {
      WidgetsBinding.instance.allowFirstFrame();
    }
  }

  void _finishSplash() {
    if (!mounted) return;
    setState(() {
      _showSplash = false;
    });
  }

  @override
  void dispose() {
    _themeController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return ThemeControllerScope(
      controller: _themeController,
      child: AnimatedBuilder(
        animation: _themeController,
        builder: (context, child) {
          return MaterialApp(
            debugShowCheckedModeBanner: false,
            theme: AppTheme.lightTheme,
            darkTheme: AppTheme.darkTheme,
            themeMode: _themeController.themeMode,
            home: !_themeReady
                ? const SizedBox.shrink()
                : _showSplash
                ? SplashScreen(onFinished: _finishSplash)
                : const MainNavigation(),
          );
        },
      ),
    );
  }
}

class QRScannerPage extends StatefulWidget {
  @override
  State<QRScannerPage> createState() => _QRScannerPageState();
}

class _QRScannerPageState extends State<QRScannerPage> {
  bool scanned = false;

  bool loading = false;

  Map<String, dynamic>? result;

  Future<void> scanURL(String url) async {
    setState(() {
      loading = true;
    });

    try {
      final response = await http.post(
        Uri.parse("http://13.126.207.254:8000/scan"),

        headers: {"Content-Type": "application/json"},

        body: jsonEncode({"url": url}),
      );

      final data = jsonDecode(response.body);

      setState(() {
        result = data;
      });
    } catch (e) {
      print(e);
    }

    setState(() {
      loading = false;
    });
  }

  Color getVerdictColor(String verdict) {
    if (verdict == "SAFE") {
      return Colors.green;
    }

    if (verdict == "SUSPICIOUS") {
      return Colors.orange;
    }

    return Colors.red;
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: Colors.black,

      appBar: AppBar(
        backgroundColor: Colors.black,

        title: const Text("QRShield", style: TextStyle(color: Colors.green)),
      ),

      body: loading
          ? const Center(child: CircularProgressIndicator())
          : result == null
          ? MobileScanner(
              onDetect: (capture) {
                if (scanned) return;

                final barcode = capture.barcodes.first;

                final code = barcode.rawValue ?? "";

                scanned = true;

                scanURL(code);
              },
            )
          : SingleChildScrollView(
              child: Padding(
                padding: const EdgeInsets.all(16),

                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,

                  children: [
                    ClipRRect(
                      borderRadius: BorderRadius.circular(16),

                      child: Image.network(
                        result!["screenshot"],
                        headers: ApiService.authorizationHeaders,
                      ),
                    ),

                    const SizedBox(height: 20),

                    Container(
                      padding: const EdgeInsets.all(16),

                      decoration: BoxDecoration(
                        color: Colors.grey[900],

                        borderRadius: BorderRadius.circular(16),
                      ),

                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,

                        children: [
                          Text(
                            "Verdict: ${result!["verdict"]}",

                            style: TextStyle(
                              color: getVerdictColor(result!["verdict"]),

                              fontSize: 24,

                              fontWeight: FontWeight.bold,
                            ),
                          ),

                          const SizedBox(height: 10),

                          Text(
                            "Risk Score: ${result!["risk_score"]}",

                            style: const TextStyle(
                              color: Colors.white,

                              fontSize: 18,
                            ),
                          ),

                          const SizedBox(height: 20),

                          const Text(
                            "Reasons",

                            style: TextStyle(
                              color: Colors.white,

                              fontSize: 20,

                              fontWeight: FontWeight.bold,
                            ),
                          ),

                          const SizedBox(height: 10),

                          ...result!["reasons"].map<Widget>((reason) {
                            return Padding(
                              padding: const EdgeInsets.only(bottom: 8),

                              child: Text(
                                "• $reason",

                                style: const TextStyle(color: Colors.white70),
                              ),
                            );
                          }).toList(),

                          const SizedBox(height: 20),

                          const Text(
                            "VirusTotal",

                            style: TextStyle(
                              color: Colors.white,

                              fontSize: 20,

                              fontWeight: FontWeight.bold,
                            ),
                          ),

                          const SizedBox(height: 10),

                          Text(
                            "Malicious: ${result!["virustotal"]["malicious"]}",

                            style: const TextStyle(color: Colors.red),
                          ),

                          Text(
                            "Suspicious: ${result!["virustotal"]["suspicious"]}",

                            style: const TextStyle(color: Colors.orange),
                          ),

                          Text(
                            "Harmless: ${result!["virustotal"]["harmless"]}",

                            style: const TextStyle(color: Colors.green),
                          ),
                        ],
                      ),
                    ),

                    const SizedBox(height: 20),

                    ElevatedButton(
                      onPressed: () {
                        setState(() {
                          scanned = false;

                          result = null;
                        });
                      },

                      child: const Text("Scan Again"),
                    ),
                  ],
                ),
              ),
            ),
    );
  }
}
