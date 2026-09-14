import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:mopro_flutter_bindings/zolana_mobile.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  await RustLib.init();
  runApp(const ZolanaMobileDemo());
}

class ZolanaMobileDemo extends StatelessWidget {
  const ZolanaMobileDemo({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Zolana Mobile',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(
          seedColor: const Color(0xff6750a4),
          brightness: Brightness.dark,
        ),
        useMaterial3: true,
      ),
      home: const DemoScreen(),
    );
  }
}

class DemoScreen extends StatefulWidget {
  const DemoScreen({super.key});

  @override
  State<DemoScreen> createState() => _DemoScreenState();
}

class _DemoScreenState extends State<DemoScreen> {
  String _sdk = 'loading';
  LocalProofResult? _proof;
  String? _error;
  bool _proving = false;

  @override
  void initState() {
    super.initState();
    _initialize();
  }

  Future<void> _initialize() async {
    try {
      final version = await sdkVersion();
      if (!mounted) return;
      setState(() => _sdk = version);
    } catch (error) {
      _showError(error);
    }
  }

  Future<void> _prove() async {
    setState(() {
      _proving = true;
      _error = null;
    });
    try {
      final keyPath = await _copyAssetToTemporaryFile(
        'assets/proving/transfer_confidential_2_3.key',
      );
      final assignmentPath = await _copyAssetToTemporaryFile(
        'assets/proving/assignment-2x3.bin',
      );
      final proof = await proveAssignment(
        provingKeyPath: keyPath,
        assignmentPath: assignmentPath,
      );
      if (!mounted) return;
      setState(() => _proof = proof);
    } catch (error) {
      _showError(error);
    } finally {
      if (mounted) setState(() => _proving = false);
    }
  }

  Future<String> _copyAssetToTemporaryFile(String asset) async {
    final data = await rootBundle.load(asset);
    final file = File('${Directory.systemTemp.path}/${asset.split('/').last}');
    await file.writeAsBytes(data.buffer.asUint8List(), flush: true);
    return file.path;
  }

  void _showError(Object error) {
    if (!mounted) return;
    setState(() => _error = error.toString());
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Zolana local prover'),
        actions: [
          Padding(
            padding: const EdgeInsets.only(right: 16),
            child: Center(child: Text('SDK $_sdk')),
          ),
        ],
      ),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          _DemoCard(
            title: 'Local Groth16 proof',
            subtitle: 'Prove and verify the staged 2→3 assignment on-device.',
            buttonLabel: 'Generate proof locally',
            busy: _proving,
            onPressed: _prove,
            child: _proof == null ? null : _ProofResult(proof: _proof!),
          ),
          if (_error != null) ...[
            const SizedBox(height: 16),
            Text(
              _error!,
              style: TextStyle(color: Theme.of(context).colorScheme.error),
            ),
          ],
        ],
      ),
    );
  }
}

class _DemoCard extends StatelessWidget {
  const _DemoCard({
    required this.title,
    required this.subtitle,
    required this.buttonLabel,
    required this.busy,
    required this.onPressed,
    this.child,
  });

  final String title;
  final String subtitle;
  final String buttonLabel;
  final bool busy;
  final VoidCallback? onPressed;
  final Widget? child;

  @override
  Widget build(BuildContext context) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(20),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(title, style: Theme.of(context).textTheme.titleLarge),
            const SizedBox(height: 6),
            Text(subtitle),
            const SizedBox(height: 16),
            FilledButton.icon(
              onPressed: busy ? null : onPressed,
              icon: busy
                  ? const SizedBox.square(
                      dimension: 18,
                      child: CircularProgressIndicator(strokeWidth: 2),
                    )
                  : const Icon(Icons.play_arrow),
              label: Text(busy ? 'Working…' : buttonLabel),
            ),
            if (child != null) ...[const SizedBox(height: 18), child!],
          ],
        ),
      ),
    );
  }
}

class _ProofResult extends StatelessWidget {
  const _ProofResult({required this.proof});

  final LocalProofResult proof;

  @override
  Widget build(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        _Detail(label: 'Verified', value: proof.verified ? 'yes' : 'no'),
        _Detail(label: 'Circuit', value: '${proof.inputs}→${proof.outputs}'),
        _Detail(label: 'Key load', value: '${proof.keyLoadMs} ms'),
        _Detail(label: 'Proving', value: '${proof.proofMs} ms'),
        _Detail(label: 'Proof JSON', value: _short(proof.proofJson)),
      ],
    );
  }
}

class _Detail extends StatelessWidget {
  const _Detail({required this.label, required this.value});

  final String label;
  final String value;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 6),
      child: Text('$label: $value'),
    );
  }
}

String _short(String value) {
  if (value.length <= 24) return value;
  return '${value.substring(0, 12)}…${value.substring(value.length - 8)}';
}
