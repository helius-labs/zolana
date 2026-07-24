import { configureGlobal } from "fast-check";

configureGlobal({
  numRuns: 100,
  seed: 1_515_146_305,
});
