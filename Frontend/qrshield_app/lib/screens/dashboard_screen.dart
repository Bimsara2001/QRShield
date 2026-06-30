import 'package:flutter/material.dart';

import '../services/history_service.dart';
import '../services/stats_service.dart';
import '../widgets/stat_card.dart';
import '../widgets/activity_tile.dart';

class DashboardScreen extends StatefulWidget {
  const DashboardScreen({super.key});

  @override
  State<DashboardScreen> createState() =>
      _DashboardScreenState();
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
      final historyData =
          await HistoryService.getHistory();

      final statsData =
          await StatsService.getStats();

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

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: const Color(0xFF050B18),

      appBar: AppBar(
        backgroundColor: const Color(0xFF050B18),
        elevation: 0,
        title: const Text(
          "QRShield",
          style: TextStyle(
            color: Colors.white,
            fontWeight: FontWeight.bold,
          ),
        ),
        actions: [
          IconButton(
            onPressed: loadDashboardData,
            icon: const Icon(
              Icons.refresh,
              color: Colors.white,
            ),
          ),
        ],
      ),

      body: loading
          ? const Center(
              child: CircularProgressIndicator(),
            )
          : SingleChildScrollView(
              padding: const EdgeInsets.all(20),
              child: Column(
                crossAxisAlignment:
                    CrossAxisAlignment.start,
                children: [
                  const Text(
                    "Advanced QR Threat Detection",
                    style: TextStyle(
                      color: Colors.white70,
                      fontSize: 16,
                    ),
                  ),

                  const SizedBox(height: 25),

                  GridView.count(
                    shrinkWrap: true,
                    physics:
                        const NeverScrollableScrollPhysics(),
                    crossAxisCount: 2,
                    crossAxisSpacing: 15,
                    mainAxisSpacing: 15,
                    childAspectRatio: 1.2,
                    children: [
                      StatCard(
                        title: "Total Scans",
                        value:
                            "${stats["total_scans"] ?? 0}",
                        icon: Icons.qr_code_scanner,
                        color: Colors.blue,
                      ),
                      StatCard(
                        title: "High Risk",
                        value:
                            "${stats["high_risk"] ?? 0}",
                        icon: Icons.warning,
                        color: Colors.red,
                      ),
                      StatCard(
                        title: "Low Risk",
                        value:
                            "${stats["low_risk"] ?? 0}",
                        icon: Icons.check_circle,
                        color: Colors.green,
                      ),
                      StatCard(
                        title: "Medium Risk",
                        value:
                            "${stats["medium_risk"] ?? 0}",
                        icon: Icons.security,
                        color: Colors.orange,
                      ),
                    ],
                  ),

                  const SizedBox(height: 30),

                  const Text(
                    "Recent Activity",
                    style: TextStyle(
                      color: Colors.white,
                      fontSize: 24,
                      fontWeight: FontWeight.bold,
                    ),
                  ),

                  const SizedBox(height: 20),

                  if (scans.isEmpty)
                    const Text(
                      "No recent activity",
                      style: TextStyle(
                        color: Colors.white70,
                      ),
                    )
                  else
                    ...scans.take(5).map((scan) {
                      return ActivityTile(
                        url: scan["title"] ??
                            scan["original_url"] ??
                            "Unknown",
                        verdict: scan["verdict"] ??
                            "No Verdict",
                      );
                    }),

                  const SizedBox(height: 20),
                ],
              ),
            ),
    );
  }
}