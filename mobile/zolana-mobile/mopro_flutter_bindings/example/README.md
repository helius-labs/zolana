# Zolana mobile demo

This app generates and verifies a Groth16 proof locally from staged 2→3
fixtures. The underlying Dart package still exposes the Zolana transaction
bindings for SDK consumers.

From the repository root:

```sh
mobile/stage-demo-assets.sh
cd mobile/zolana-mobile/mopro_flutter_bindings/example
flutter run
```

The fixture files are large and ignored by Git. See `../../../README.md` for
the SDK architecture and current limitations.
