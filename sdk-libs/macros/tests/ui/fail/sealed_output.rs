use zolana_program::circuit::CircuitOutput;

// Only the SDK binds an output to the public inputs: a custom output names its
// public hash through PublicHashOutput instead.
struct CustomOutput;

impl CircuitOutput for CustomOutput {}

fn main() {}
