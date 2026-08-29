import 'package:flutter/material.dart';

import 'metric_card.dart';

/// Backward-compatible dashboard metric wrapper.
///
/// Existing callers can continue using [StatCard] while the visual treatment is
/// shared with the new [MetricCard] design component.
class StatCard extends StatelessWidget {
  final String title;
  final String value;
  final IconData icon;
  final Color color;
  final String caption;

  const StatCard({
    super.key,
    required this.title,
    required this.value,
    required this.icon,
    required this.color,
    this.caption = 'All scans',
  });

  @override
  Widget build(BuildContext context) {
    return MetricCard(
      title: title,
      value: value,
      icon: icon,
      color: color,
      caption: caption,
    );
  }
}
