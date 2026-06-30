import 'package:flutter/material.dart';

import '../services/history_service.dart';
import 'result_screen.dart';

class HistoryScreen extends StatefulWidget {
  const HistoryScreen({super.key});

  @override
  State<HistoryScreen> createState() =>
      _HistoryScreenState();
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
      final title =
          (scan["title"] ?? "").toString().toLowerCase();

      final url =
          (scan["original_url"] ?? "").toString().toLowerCase();

      final verdict =
          (scan["verdict"] ?? "").toString();

      final matchesSearch =
          title.contains(searchQuery.toLowerCase()) ||
          url.contains(searchQuery.toLowerCase());

      final matchesFilter =
          selectedFilter == "All"
              ? true
              : verdict == selectedFilter;

      return matchesSearch && matchesFilter;
    }).toList();
  }

  Color getColor(String verdict) {
    if (verdict == "Low Risk") return Colors.green;
    if (verdict == "Medium Risk") return Colors.orange;
    return Colors.red;
  }

  Widget filterChip(String label) {
    final selected = selectedFilter == label;

    return ChoiceChip(
      label: Text(label),
      selected: selected,
      selectedColor: Colors.blueAccent,
      backgroundColor: const Color(0xFF0B1220),
      labelStyle: TextStyle(
        color: selected ? Colors.white : Colors.white70,
      ),
      onSelected: (_) {
        setState(() {
          selectedFilter = label;
        });
      },
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: const Color(0xFF050B18),

      appBar: AppBar(
        backgroundColor: const Color(0xFF050B18),
        elevation: 0,
        title: const Text(
          "Scan History",
          style: TextStyle(color: Colors.white),
        ),
      ),

      body: loading
          ? const Center(child: CircularProgressIndicator())
          : Column(
              children: [
                Padding(
                  padding: const EdgeInsets.all(12),
                  child: TextField(
                    style: const TextStyle(color: Colors.white),
                    decoration: InputDecoration(
                      hintText: "Search URL or title...",
                      hintStyle:
                          const TextStyle(color: Colors.white54),
                      prefixIcon: const Icon(
                        Icons.search,
                        color: Colors.white54,
                      ),
                      filled: true,
                      fillColor: const Color(0xFF0B1220),
                      border: OutlineInputBorder(
                        borderRadius: BorderRadius.circular(16),
                        borderSide: BorderSide.none,
                      ),
                    ),
                    onChanged: (value) {
                      setState(() {
                        searchQuery = value;
                      });
                    },
                  ),
                ),

                SingleChildScrollView(
                  scrollDirection: Axis.horizontal,
                  padding: const EdgeInsets.symmetric(horizontal: 12),
                  child: Row(
                    children: [
                      filterChip("All"),
                      const SizedBox(width: 8),
                      filterChip("Low Risk"),
                      const SizedBox(width: 8),
                      filterChip("Medium Risk"),
                      const SizedBox(width: 8),
                      filterChip("High Risk"),
                    ],
                  ),
                ),

                const SizedBox(height: 8),

                Expanded(
                  child: filteredScans.isEmpty
                      ? RefreshIndicator(
                          onRefresh: loadHistory,
                          child: ListView(
                            children: const [
                              SizedBox(height: 250),
                              Center(
                                child: Text(
                                  "No matching scans",
                                  style: TextStyle(
                                    color: Colors.white70,
                                    fontSize: 18,
                                  ),
                                ),
                              ),
                            ],
                          ),
                        )
                      : RefreshIndicator(
                          onRefresh: loadHistory,
                          child: ListView.builder(
                            itemCount: filteredScans.length,
                            itemBuilder: (context, index) {
                              final scan = filteredScans[index];

                              return Card(
                                color: const Color(0xFF0B1220),
                                margin:
                                    const EdgeInsets.symmetric(
                                  horizontal: 12,
                                  vertical: 8,
                                ),
                                shape: RoundedRectangleBorder(
                                  borderRadius:
                                      BorderRadius.circular(16),
                                ),
                                child: InkWell(
                                  borderRadius:
                                      BorderRadius.circular(16),
                                  onTap: () {
                                    Navigator.push(
                                      context,
                                      MaterialPageRoute(
                                        builder: (_) =>
                                            ResultScreen(
                                          result: scan,
                                        ),
                                      ),
                                    );
                                  },
                                  child: ListTile(
                                    contentPadding:
                                        const EdgeInsets.all(12),
                                    leading: ClipRRect(
                                      borderRadius:
                                          BorderRadius.circular(10),
                                      child: Image.network(
                                        scan["screenshot"] ?? "",
                                        width: 60,
                                        height: 60,
                                        fit: BoxFit.cover,
                                        errorBuilder:
                                            (context, error, stackTrace) {
                                          return Container(
                                            width: 60,
                                            height: 60,
                                            color: Colors.grey,
                                            child: const Icon(
                                              Icons.image,
                                              color: Colors.white,
                                            ),
                                          );
                                        },
                                      ),
                                    ),
                                    title: Text(
                                      scan["title"] ?? "Unknown",
                                      style: const TextStyle(
                                        color: Colors.white,
                                        fontWeight: FontWeight.bold,
                                      ),
                                    ),
                                    subtitle: Column(
                                      crossAxisAlignment:
                                          CrossAxisAlignment.start,
                                      children: [
                                        Text(
                                          scan["verdict"] ??
                                              "No Verdict",
                                          style: TextStyle(
                                            color: getColor(
                                              scan["verdict"] ??
                                                  "Unknown",
                                            ),
                                          ),
                                        ),
                                        const SizedBox(height: 4),
                                        Text(
                                          "Risk Score: ${scan["risk_score"] ?? "-"}",
                                          style: const TextStyle(
                                            color: Colors.white70,
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
                ),
              ],
            ),
    );
  }
}