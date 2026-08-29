import 'dart:convert';
import 'package:http/http.dart' as http;
import 'api_service.dart';

class StatsService {
  static const String baseUrl = ApiService.baseUrl;

  static Future<Map<String, dynamic>> getStats() async {
    final response = await http.get(
      Uri.parse("$baseUrl/stats"),
      headers: ApiService.authorizationHeaders,
    );

    return jsonDecode(response.body);
  }
}
