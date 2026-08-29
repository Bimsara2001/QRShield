import 'package:flutter_test/flutter_test.dart';
import 'package:qrshield_app/services/api_service.dart';

void main() {
  test('rewrites stale absolute localhost screenshot URLs', () {
    expect(
      ApiService.backendAssetUrl('http://localhost:8000/screenshots/abc.png'),
      'http://127.0.0.1:8004/screenshots/abc.png',
    );
  });

  test('resolves relative screenshot paths against the active backend', () {
    expect(
      ApiService.backendAssetUrl('/screenshots/abc.png'),
      'http://127.0.0.1:8004/screenshots/abc.png',
    );
  });

  test('does not rewrite arbitrary external URLs', () {
    const external = 'https://cdn.example.test/screenshots/abc.png';
    expect(ApiService.backendAssetUrl(external), external);
  });
}
