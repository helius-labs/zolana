import { beforeAll } from "vitest";

import { initializePoseidon } from "../src/hasher/index.js";

beforeAll(async () => {
  await initializePoseidon();
});
