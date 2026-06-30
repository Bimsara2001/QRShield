import 'package:flutter/material.dart';

class StatCard extends StatelessWidget {

  final String title;
  final String value;
  final IconData icon;
  final Color color;

  const StatCard({
    super.key,
    required this.title,
    required this.value,
    required this.icon,
    required this.color,
  });

  @override
  Widget build(BuildContext context) {

    return Container(

      padding: const EdgeInsets.all(20),

      decoration: BoxDecoration(

        color: const Color(0xFF111827),

        borderRadius: BorderRadius.circular(20),
      ),

      child: Column(

        mainAxisAlignment: MainAxisAlignment.center,

        children: [

          Icon(
            icon,
            size: 40,
            color: color,
          ),

          const SizedBox(height: 10),

          Text(
            value,
            style: const TextStyle(
              color: Colors.white,
              fontSize: 28,
              fontWeight: FontWeight.bold,
            ),
          ),

          const SizedBox(height: 5),

          Text(
            title,
            style: const TextStyle(
              color: Colors.white70,
            ),
          ),
        ],
      ),
    );
  }
}