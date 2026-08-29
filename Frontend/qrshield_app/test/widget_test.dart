import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:qrshield_app/theme/app_colors.dart';
import 'package:qrshield_app/theme/app_theme.dart';
import 'package:qrshield_app/widgets/screen_header.dart';

void main() {
  testWidgets('renders the QRShield visual system', (tester) async {
    // The production theme uses Google Fonts. The smoke test deliberately uses
    // system text styles so it remains offline and does not require a font
    // download, backend, or camera.
    final smokeTheme = AppTheme.darkTheme.copyWith(
      textTheme: ThemeData.dark().textTheme,
    );

    await tester.pumpWidget(
      MaterialApp(
        theme: smokeTheme,
        home: const Scaffold(
          body: Center(
            child: ScreenHeader(
              title: 'QRShield',
              subtitle: 'Advanced QR Threat Detection',
            ),
          ),
        ),
      ),
    );

    expect(find.text('QRShield'), findsOneWidget);
    expect(find.text('Advanced QR Threat Detection'), findsOneWidget);

    final context = tester.element(find.byType(Scaffold));
    expect(Theme.of(context).brightness, Brightness.dark);
    expect(Theme.of(context).scaffoldBackgroundColor, AppColors.background);
  });
}
