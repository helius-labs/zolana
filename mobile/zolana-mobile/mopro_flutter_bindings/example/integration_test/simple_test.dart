import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:mopro_flutter_bindings/zolana_mobile.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  setUpAll(RustLib.init);

  testWidgets('prepares a compact private transfer in Rust', (tester) async {
    final recipient = await shieldedAddress(seed: List.filled(32, 8));
    final draft = await prepareTransfer(
      request: TransferDraftRequest(
        senderSeed: Uint8List.fromList(List.filled(32, 7)),
        recipient: recipient,
        inputLamports: BigInt.from(10),
        transferLamports: BigInt.from(4),
      ),
    );

    expect(draft.shape, '1→2');
    expect(draft.changeLamports, BigInt.from(6));
    expect(draft.outputs, hasLength(2));
  });
}
