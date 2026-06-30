import 'dart:convert';
import 'package:http/http.dart' as http;

class ApiService {

  static const String baseUrl =
      "http://localhost:8000";

  static Future<Map<String, dynamic>>
      scanUrl(String url) async {

    final response = await http.post(

      Uri.parse("$baseUrl/scan"),

      headers: {
        "Content-Type": "application/json",
      },

      body: jsonEncode({
        "url": url,
      }),
    );

    return jsonDecode(response.body);
  }
}