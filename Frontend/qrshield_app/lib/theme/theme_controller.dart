import 'package:flutter/material.dart';
import 'package:shared_preferences/shared_preferences.dart';

/// Owns the app-wide QRShield theme preference.
///
/// The default remains dark so the existing product appearance is shown while
/// an asynchronously persisted preference is loaded after startup.
class ThemeController extends ChangeNotifier {
  ThemeController({SharedPreferencesAsync? preferences})
    : _preferences = preferences ?? SharedPreferencesAsync();

  static const String preferenceKey = 'qrshield_theme_mode';

  final SharedPreferencesAsync _preferences;
  ThemeMode _themeMode = ThemeMode.dark;

  ThemeMode get themeMode => _themeMode;

  Future<void> load() async {
    try {
      final storedValue = await _preferences.getString(preferenceKey);
      final loadedMode = _fromStoredValue(storedValue);
      if (_themeMode != loadedMode) {
        _themeMode = loadedMode;
        notifyListeners();
      }
    } catch (_) {
      // Keep the default dark theme when platform storage is unavailable.
    }
  }

  Future<void> setThemeMode(ThemeMode mode) async {
    if (_themeMode != mode) {
      _themeMode = mode;
      notifyListeners();
    }

    try {
      await _preferences.setString(preferenceKey, _storedValue(mode));
    } catch (_) {
      // The selected theme remains active for this session if saving fails.
    }
  }

  static ThemeMode _fromStoredValue(String? value) {
    switch (value) {
      case 'light':
        return ThemeMode.light;
      case 'system':
        return ThemeMode.system;
      case 'dark':
      default:
        return ThemeMode.dark;
    }
  }

  static String _storedValue(ThemeMode mode) {
    switch (mode) {
      case ThemeMode.light:
        return 'light';
      case ThemeMode.system:
        return 'system';
      case ThemeMode.dark:
        return 'dark';
    }
  }
}

/// Makes the app-wide [ThemeController] available without changing the
/// existing navigation tree or individual screen constructors.
class ThemeControllerScope extends InheritedNotifier<ThemeController> {
  const ThemeControllerScope({
    super.key,
    required ThemeController controller,
    required super.child,
  }) : super(notifier: controller);

  static ThemeController of(BuildContext context) {
    final scope =
        context.dependOnInheritedWidgetOfExactType<ThemeControllerScope>();
    if (scope == null || scope.notifier == null) {
      throw StateError('ThemeControllerScope is not available in this context.');
    }
    return scope.notifier!;
  }
}
