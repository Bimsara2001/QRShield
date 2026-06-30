import 'package:flutter/material.dart';

class ActivityTile extends StatelessWidget {

  final String url;
  final String verdict;

  const ActivityTile({
    super.key,
    required this.url,
    required this.verdict,
  });

  Color getColor() {

    if(verdict == "Low Risk") {
      return Colors.green;
    }

    if(verdict == "Medium Risk") {
      return Colors.orange;
    }

    return Colors.red;
  }

  @override
  Widget build(BuildContext context) {

    return Container(

      margin: const EdgeInsets.only(bottom: 12),

      padding: const EdgeInsets.all(16),

      decoration: BoxDecoration(

        color: const Color(0xFF111827),

        borderRadius: BorderRadius.circular(16),
      ),

      child: Row(

        children: [

          Icon(
            Icons.language,
            color: getColor(),
          ),

          const SizedBox(width: 12),

          Expanded(

            child: Column(

              crossAxisAlignment:
                  CrossAxisAlignment.start,

              children: [

                Text(
                  url,
                  style: const TextStyle(
                    color: Colors.white,
                    fontWeight: FontWeight.bold,
                  ),
                ),

                Text(
                  verdict,
                  style: TextStyle(
                    color: getColor(),
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }
}