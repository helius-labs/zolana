import { readFile } from "node:fs/promises";
import { createMockGateway, createRecipientRouter, listen } from "./gateway.mjs";

const path = process.argv[2];
if (!path || !process.env.ZOLANA_MOCK_API_KEY) {
  console.error(
    "Usage: ZOLANA_MOCK_API_KEY=<test-key> node tools/tee-fleet/serve.mjs <config.json>",
  );
  process.exitCode = 1;
} else {
  const config = JSON.parse(await readFile(path, "utf8"));
  const router = createRecipientRouter({ deployments: config.deployments });
  const routerServer = await listen(router.handler);
  try {
    const gateway = createMockGateway({
      apiKey: process.env.ZOLANA_MOCK_API_KEY,
      origin: routerServer.url,
      allowedOrigins: config.allowedOrigins ?? [],
    });
    const publicServer = await listen(gateway.handler, config.port ?? 3301);
    console.log(`Mock GK: ${publicServer.url}/v1/zolana (API key supplied separately)`);
    let stopping = false;
    const stop = async () => {
      if (stopping) return;
      stopping = true;
      await publicServer.close();
      await routerServer.close();
    };
    process.once("SIGINT", stop);
    process.once("SIGTERM", stop);
  } catch (error) {
    await routerServer.close();
    throw error;
  }
}
