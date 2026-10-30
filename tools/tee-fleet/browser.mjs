import { chromium, firefox, webkit } from "playwright";

export async function launchBrowser() {
  const selected = process.env.ZOLANA_TEST_BROWSER ?? "chromium";
  const browsers = { chromium, firefox, webkit };
  if (!Object.hasOwn(browsers, selected)) throw new Error("expected chromium, firefox or webkit");
  const executablePath = selected === "chromium" ? process.env.ZOLANA_CHROME_EXECUTABLE : undefined;
  return browsers[selected].launch(executablePath ? { executablePath } : {});
}
