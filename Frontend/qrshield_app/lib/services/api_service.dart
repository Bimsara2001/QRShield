import 'dart:convert';
import 'package:http/http.dart' as http;

class ScanException implements Exception {
  final String message;

  const ScanException(this.message);

  @override
  String toString() => message;
}

class ApiService {
  /// Configure release/development endpoints with --dart-define rather than
  /// committing environment-specific values into the application source.
  static const String baseUrl = String.fromEnvironment(
    'QRSHIELD_API_BASE_URL',
    defaultValue: 'http://13.126.207.254:8000',
  );
  static const String _apiToken = String.fromEnvironment('QRSHIELD_API_TOKEN');

  static Uri get _baseUri => Uri.parse(baseUrl);

  /// Resolves backend-owned asset paths against [baseUrl]. Stale absolute
  /// localhost URLs returned by older backend instances are converted, while
  /// arbitrary external URLs are left untouched.
  static String backendAssetUrl(String value) {
    final raw = value.trim();
    if (raw.isEmpty) return raw;

    final parsed = Uri.tryParse(raw);
    if (parsed == null) return raw;

    if (!parsed.hasScheme && !parsed.hasAuthority) {
      final path = raw.startsWith('/') ? raw : '/$raw';
      return _baseUri.resolve(path).toString();
    }

    if (parsed.hasScheme &&
        parsed.hasAuthority &&
        _isBackendHost(parsed.host)) {
      final path = parsed.path.isEmpty ? '/' : parsed.path;
      return _baseUri
          .resolve(path)
          .replace(
            query: parsed.hasQuery ? parsed.query : null,
            fragment: parsed.hasFragment ? parsed.fragment : null,
          )
          .toString();
    }

    return raw;
  }

  static bool _isBackendHost(String host) {
    final normalized = host.toLowerCase();
    final activeHost = _baseUri.host.toLowerCase();
    return normalized == activeHost ||
        normalized == 'localhost' ||
        normalized == '127.0.0.1' ||
        normalized == '::1';
  }

  /// Header used for scan history, screenshots, and scan submission when the
  /// backend-sensitive-route token is configured.
  static Map<String, String> get authorizationHeaders {
    if (_apiToken.trim().isEmpty) return const {};
    return {'X-QRShield-Api-Token': _apiToken};
  }

  static Map<String, String> get jsonAuthorizationHeaders => {
    'Content-Type': 'application/json',
    ...authorizationHeaders,
  };

  static Future<Map<String, dynamic>> scanUrl(String url) {
    return _postForSuccessfulScan('/scan', {'url': url});
  }

  /// Calls the explicit backend-only inert fixture harness. This method is
  /// reachable only from a [kDebugMode]-guarded Settings control.
  static Future<Map<String, dynamic>> runControlledHighRiskTest() {
    return _postForSuccessfulScan('/test/controlled-scan', const {
      'fixture': 'fake_banking_login',
    });
  }

  static Future<Map<String, dynamic>> _postForSuccessfulScan(
    String path,
    Map<String, dynamic> body,
  ) async {
    final response = await http.post(
      Uri.parse('$baseUrl$path'),
      headers: jsonAuthorizationHeaders,
      body: jsonEncode(body),
    );

    if (response.statusCode < 200 || response.statusCode >= 300) {
      throw const ScanException(
        'Unable to complete security analysis. Please try again.',
      );
    }

    dynamic decoded;
    try {
      decoded = jsonDecode(response.body);
    } on FormatException {
      throw const ScanException(
        'Unable to complete security analysis. Please try again.',
      );
    }

    if (decoded is! Map) {
      throw const ScanException(
        'Unable to complete security analysis. Please try again.',
      );
    }

    final result = Map<String, dynamic>.from(decoded);
    if (result['status'] != 'success') {
      final message = result['message'];
      throw ScanException(
        message is String && message.trim().isNotEmpty
            ? message
            : 'Unable to complete security analysis. Please try again.',
      );
    }

    const requiredFields = [
      'status',
      'original_url',
      'final_url',
      'title',
      'screenshot',
      'risk_score',
      'verdict',
      'reasons',
      'virustotal',
    ];
    final hasAllFields = requiredFields.every(result.containsKey);
    final hasValidTypes =
        result['original_url'] is String &&
        result['final_url'] is String &&
        result['title'] is String &&
        result['screenshot'] is String &&
        result['risk_score'] is num &&
        result['verdict'] is String &&
        result['reasons'] is List &&
        result['virustotal'] is Map;
    final hasRequiredValues =
        (result['original_url'] as String).trim().isNotEmpty &&
        (result['final_url'] as String).trim().isNotEmpty &&
        (result['screenshot'] as String).trim().isNotEmpty &&
        (result['verdict'] as String).trim().isNotEmpty;

    if (!hasAllFields || !hasValidTypes || !hasRequiredValues) {
      throw const ScanException(
        'Unable to complete security analysis. Please try again.',
      );
    }

    result['screenshot'] = backendAssetUrl(result['screenshot'] as String);
    return result;
  }
}
