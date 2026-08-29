import 'dart:convert';
import 'package:http/http.dart' as http;
import 'api_service.dart';

class HealthService {
  static const String baseUrl = ApiService.baseUrl;

  static Future<bool> checkBackend() async {
    try {
      final response = await http.get(
        Uri.parse(baseUrl),
      );

      if (response.statusCode == 200) {
        final data = jsonDecode(response.body);

        return data["message"] ==
            "QRShield Sandbox Running";
      }

      return false;
    } catch (e) {
      return false;
    }
  }
}
