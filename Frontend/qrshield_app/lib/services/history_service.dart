import 'dart:convert';
import 'package:http/http.dart' as http;
import 'api_service.dart';

class HistoryService {
  static const String baseUrl = ApiService.baseUrl;

  static Future<List<dynamic>> getHistory() async {
    final response = await http.get(
      Uri.parse("$baseUrl/history"),
      headers: ApiService.authorizationHeaders,
    );

    final decoded = jsonDecode(response.body);

    if (decoded is List) {
      return _normalizeScreenshots(decoded);
    }

    if (decoded is Map && decoded["data"] is List) {
      return _normalizeScreenshots(decoded["data"]);
    }

    return [];
  }

  static List<dynamic> _normalizeScreenshots(List<dynamic> scans) {
    return scans.map((scan) {
      if (scan is! Map || scan['screenshot'] is! String) return scan;
      return {
        ...Map<String, dynamic>.from(scan),
        'screenshot': ApiService.backendAssetUrl(scan['screenshot'] as String),
      };
    }).toList();
  }

  static Future<bool> clearHistory() async {
    final response = await http.delete(
      Uri.parse("$baseUrl/history"),
      headers: ApiService.authorizationHeaders,
    );

    return response.statusCode == 200;
  }
}
