import 'dart:convert';
import 'package:http/http.dart' as http;

class StatsService {
  static const String baseUrl =
      "http://localhost:8000";

  static Future<Map<String, dynamic>> getStats() async {
    final response = await http.get(
      Uri.parse("$baseUrl/stats"),
    );

    return jsonDecode(response.body);
  }
}