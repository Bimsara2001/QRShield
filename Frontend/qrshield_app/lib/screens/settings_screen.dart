import 'package:flutter/material.dart';

import '../services/history_service.dart';
import '../services/health_service.dart';

class SettingsScreen extends StatefulWidget {
  const SettingsScreen({super.key});

  @override
  State<SettingsScreen> createState() =>
      _SettingsScreenState();
}

class _SettingsScreenState
    extends State<SettingsScreen> {
  bool checkingBackend = true;
  bool backendConnected = false;

  @override
  void initState() {
    super.initState();
    checkBackendStatus();
  }

  Future<void> checkBackendStatus() async {
    setState(() {
      checkingBackend = true;
    });

    final status =
        await HealthService.checkBackend();

    if (!mounted) return;

    setState(() {
      backendConnected = status;
      checkingBackend = false;
    });
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: const Color(0xFF050B18),

      appBar: AppBar(
        backgroundColor: const Color(0xFF050B18),
        elevation: 0,
        title: const Text(
          "Settings",
          style: TextStyle(color: Colors.white),
        ),
        actions: [
          IconButton(
            onPressed: checkBackendStatus,
            icon: const Icon(
              Icons.refresh,
              color: Colors.white,
            ),
          ),
        ],
      ),

      body: ListView(
        padding: const EdgeInsets.all(20),
        children: [
          Card(
            color: const Color(0xFF0B1220),
            child: ListTile(
              leading: const Icon(
                Icons.info,
                color: Colors.blue,
              ),
              title: const Text(
                "App Version",
                style: TextStyle(color: Colors.white),
              ),
              subtitle: const Text(
                "1.0.0",
                style: TextStyle(color: Colors.white70),
              ),
            ),
          ),

          Card(
            color: const Color(0xFF0B1220),
            child: ListTile(
              leading: Icon(
                backendConnected
                    ? Icons.cloud_done
                    : Icons.cloud_off,
                color: backendConnected
                    ? Colors.green
                    : Colors.red,
              ),
              title: const Text(
                "Backend Status",
                style: TextStyle(color: Colors.white),
              ),
              subtitle: Text(
                checkingBackend
                    ? "Checking..."
                    : backendConnected
                        ? "Connected"
                        : "Disconnected",
                style: const TextStyle(
                  color: Colors.white70,
                ),
              ),
            ),
          ),

          Card(
            color: const Color(0xFF0B1220),
            child: ListTile(
              leading: const Icon(
                Icons.delete,
                color: Colors.red,
              ),
              title: const Text(
                "Clear History",
                style: TextStyle(color: Colors.white),
              ),
              onTap: () async {
                final confirm =
                    await showDialog<bool>(
                  context: context,
                  builder: (context) {
                    return AlertDialog(
                      backgroundColor:
                          const Color(0xFF0B1220),
                      title: const Text(
                        "Clear History",
                        style: TextStyle(
                          color: Colors.white,
                        ),
                      ),
                      content: const Text(
                        "Are you sure you want to delete all scan history?",
                        style: TextStyle(
                          color: Colors.white70,
                        ),
                      ),
                      actions: [
                        TextButton(
                          onPressed: () {
                            Navigator.pop(
                              context,
                              false,
                            );
                          },
                          child: const Text("Cancel"),
                        ),
                        TextButton(
                          onPressed: () {
                            Navigator.pop(
                              context,
                              true,
                            );
                          },
                          child: const Text(
                            "Delete",
                            style: TextStyle(
                              color: Colors.red,
                            ),
                          ),
                        ),
                      ],
                    );
                  },
                );

                if (confirm != true) return;

                final success =
                    await HistoryService.clearHistory();

                if (!context.mounted) return;

                ScaffoldMessenger.of(context)
                    .showSnackBar(
                  SnackBar(
                    content: Text(
                      success
                          ? "History cleared successfully"
                          : "Failed to clear history",
                    ),
                  ),
                );
              },
            ),
          ),

          const SizedBox(height: 20),

          Container(
            padding: const EdgeInsets.all(20),
            decoration: BoxDecoration(
              color: const Color(0xFF0B1220),
              borderRadius:
                  BorderRadius.circular(16),
            ),
            child: const Column(
              children: [
                Text(
                  "QRShield",
                  style: TextStyle(
                    color: Colors.white,
                    fontSize: 22,
                    fontWeight: FontWeight.bold,
                  ),
                ),
                SizedBox(height: 10),
                Text(
                  "QR Code Threat Detection Platform",
                  textAlign: TextAlign.center,
                  style: TextStyle(
                    color: Colors.white70,
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