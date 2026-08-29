import 'package:flutter/material.dart';

/// Shared QRShield color tokens.
///
/// Keep semantic risk colors separate from their low-opacity surface variants
/// so status UI remains consistent across the application.
class AppColors {
  AppColors._();

  static const Color background = Color(0xFF050B18);
  static const Color backgroundSecondary = Color(0xFF07101F);

  static const Color surface = Color(0xFF0B1424);
  static const Color surfaceElevated = Color(0xFF101B2D);
  static const Color surfaceSoft = Color(0xFF111C2E);

  static const Color primaryBlue = Color(0xFF2F9BFF);
  static const Color primaryBlueBright = Color(0xFF46B5FF);
  static const Color blueDark = Color(0xFF0D65D9);
  static const Color primaryBlueSoft = Color(0x1F2F9BFF);
  static const Color blueGlow = Color(0x332F9BFF);

  static const Color border = Color(0xFF1C2B42);
  static const Color borderBright = Color(0xFF244B73);

  static const Color textPrimary = Color(0xFFF5F8FF);
  static const Color textSecondary = Color(0xFFA9B4C7);
  static const Color textMuted = Color(0xFF68758A);

  static const Color safe = Color(0xFF46D369);
  static const Color safeBackground = Color(0x1F46D369);

  static const Color medium = Color(0xFFFF9F1A);
  static const Color mediumBackground = Color(0x1FFF9F1A);

  static const Color danger = Color(0xFFFF4D4F);
  static const Color dangerBackground = Color(0x1FFF4D4F);
}

/// Theme-aware structural color tokens for the QRShield interface.
///
/// Brand and semantic risk colors remain in [AppColors]. This extension
/// supplies the surfaces, borders, and text colors that need to adapt when
/// the user switches between the dark and light QRShield themes.
class QrShieldPalette extends ThemeExtension<QrShieldPalette> {
  const QrShieldPalette({
    required this.background,
    required this.backgroundSecondary,
    required this.surface,
    required this.surfaceElevated,
    required this.surfaceSoft,
    required this.primaryBlueSoft,
    required this.blueGlow,
    required this.border,
    required this.borderBright,
    required this.textPrimary,
    required this.textSecondary,
    required this.textMuted,
    required this.safeBackground,
    required this.mediumBackground,
    required this.dangerBackground,
    required this.shadow,
    required this.isDark,
  });

  const QrShieldPalette.dark()
    : background = AppColors.background,
      backgroundSecondary = AppColors.backgroundSecondary,
      surface = AppColors.surface,
      surfaceElevated = AppColors.surfaceElevated,
      surfaceSoft = AppColors.surfaceSoft,
      primaryBlueSoft = AppColors.primaryBlueSoft,
      blueGlow = AppColors.blueGlow,
      border = AppColors.border,
      borderBright = AppColors.borderBright,
      textPrimary = AppColors.textPrimary,
      textSecondary = AppColors.textSecondary,
      textMuted = AppColors.textMuted,
      safeBackground = AppColors.safeBackground,
      mediumBackground = AppColors.mediumBackground,
      dangerBackground = AppColors.dangerBackground,
      shadow = const Color(0x66000000),
      isDark = true;

  const QrShieldPalette.light()
    : background = const Color(0xFFF3F7FC),
      backgroundSecondary = const Color(0xFFE9F0F8),
      surface = Colors.white,
      surfaceElevated = const Color(0xFFF9FBFE),
      surfaceSoft = const Color(0xFFEAF1F8),
      primaryBlueSoft = const Color(0x1F2F9BFF),
      blueGlow = const Color(0x262F9BFF),
      border = const Color(0xFFD5E0ED),
      borderBright = const Color(0xFFB5CDE6),
      textPrimary = const Color(0xFF102033),
      textSecondary = const Color(0xFF506176),
      textMuted = const Color(0xFF748398),
      safeBackground = const Color(0x1F46D369),
      mediumBackground = const Color(0x1FFF9F1A),
      dangerBackground = const Color(0x1FFF4D4F),
      shadow = const Color(0x1A102033),
      isDark = false;

  final Color background;
  final Color backgroundSecondary;
  final Color surface;
  final Color surfaceElevated;
  final Color surfaceSoft;
  final Color primaryBlueSoft;
  final Color blueGlow;
  final Color border;
  final Color borderBright;
  final Color textPrimary;
  final Color textSecondary;
  final Color textMuted;
  final Color safeBackground;
  final Color mediumBackground;
  final Color dangerBackground;
  final Color shadow;
  final bool isDark;

  @override
  QrShieldPalette copyWith({
    Color? background,
    Color? backgroundSecondary,
    Color? surface,
    Color? surfaceElevated,
    Color? surfaceSoft,
    Color? primaryBlueSoft,
    Color? blueGlow,
    Color? border,
    Color? borderBright,
    Color? textPrimary,
    Color? textSecondary,
    Color? textMuted,
    Color? safeBackground,
    Color? mediumBackground,
    Color? dangerBackground,
    Color? shadow,
    bool? isDark,
  }) {
    return QrShieldPalette(
      background: background ?? this.background,
      backgroundSecondary: backgroundSecondary ?? this.backgroundSecondary,
      surface: surface ?? this.surface,
      surfaceElevated: surfaceElevated ?? this.surfaceElevated,
      surfaceSoft: surfaceSoft ?? this.surfaceSoft,
      primaryBlueSoft: primaryBlueSoft ?? this.primaryBlueSoft,
      blueGlow: blueGlow ?? this.blueGlow,
      border: border ?? this.border,
      borderBright: borderBright ?? this.borderBright,
      textPrimary: textPrimary ?? this.textPrimary,
      textSecondary: textSecondary ?? this.textSecondary,
      textMuted: textMuted ?? this.textMuted,
      safeBackground: safeBackground ?? this.safeBackground,
      mediumBackground: mediumBackground ?? this.mediumBackground,
      dangerBackground: dangerBackground ?? this.dangerBackground,
      shadow: shadow ?? this.shadow,
      isDark: isDark ?? this.isDark,
    );
  }

  @override
  QrShieldPalette lerp(covariant QrShieldPalette? other, double t) {
    if (other is! QrShieldPalette) {
      return this;
    }

    return QrShieldPalette(
      background: Color.lerp(background, other.background, t)!,
      backgroundSecondary:
          Color.lerp(backgroundSecondary, other.backgroundSecondary, t)!,
      surface: Color.lerp(surface, other.surface, t)!,
      surfaceElevated:
          Color.lerp(surfaceElevated, other.surfaceElevated, t)!,
      surfaceSoft: Color.lerp(surfaceSoft, other.surfaceSoft, t)!,
      primaryBlueSoft:
          Color.lerp(primaryBlueSoft, other.primaryBlueSoft, t)!,
      blueGlow: Color.lerp(blueGlow, other.blueGlow, t)!,
      border: Color.lerp(border, other.border, t)!,
      borderBright: Color.lerp(borderBright, other.borderBright, t)!,
      textPrimary: Color.lerp(textPrimary, other.textPrimary, t)!,
      textSecondary: Color.lerp(textSecondary, other.textSecondary, t)!,
      textMuted: Color.lerp(textMuted, other.textMuted, t)!,
      safeBackground: Color.lerp(safeBackground, other.safeBackground, t)!,
      mediumBackground:
          Color.lerp(mediumBackground, other.mediumBackground, t)!,
      dangerBackground:
          Color.lerp(dangerBackground, other.dangerBackground, t)!,
      shadow: Color.lerp(shadow, other.shadow, t)!,
      isDark: t < 0.5 ? isDark : other.isDark,
    );
  }
}

extension QrShieldPaletteContext on BuildContext {
  /// The active QRShield structural palette.
  ///
  /// The fallback retains the existing dark appearance if this extension is
  /// read above [MaterialApp] during startup.
  QrShieldPalette get qrPalette =>
      Theme.of(this).extension<QrShieldPalette>() ?? const QrShieldPalette.dark();
}
