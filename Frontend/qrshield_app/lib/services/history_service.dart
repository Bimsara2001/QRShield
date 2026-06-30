import 'dart:convert';
import 'package:http/http.dart' as http;

class HistoryService {
  static const String baseUrl =
      "http://localhost:8000";

  static Future<List<dynamic>> getHistory() async {
    final response = await http.get(
      Uri.parse("$baseUrl/history"),
    );

    final decoded = jsonDecode(response.body);

    if (decoded is List) {
      return decoded;
    }

    if (decoded is Map &&
        decoded["data"] is List) {
      return decoded["data"];
    }

    return [];
  }

  static Future<bool> clearHistory() async {
    final response = await http.delete(
      Uri.parse("$baseUrl/history"),
    );

    return response.statusCode == 200;
  }
}