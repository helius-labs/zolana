import { access, cp, mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import path from "node:path";
import semver from "semver";

function parseArguments(argv) {
  const argumentsByName = new Map();
  for (let index = 0; index < argv.length; index += 2) {
    const name = argv[index];
    const value = argv[index + 1];
    if (!name?.startsWith("--") || value === undefined) {
      throw new Error(`expected --name value arguments, received ${argv.join(" ")}`);
    }
    argumentsByName.set(name.slice(2), value);
  }
  return argumentsByName;
}

function requiredArgument(argumentsByName, name) {
  const value = argumentsByName.get(name);
  if (!value) {
    throw new Error(`missing required --${name} argument`);
  }
  return value;
}

function parseVersion(value) {
  const parsed = semver.parse(value);
  if (!parsed || parsed.version !== value || parsed.build.length !== 0) {
    throw new Error(`version must be SemVer without build metadata: ${value}`);
  }
  return {
    value,
    prerelease: parsed.prerelease,
  };
}

function comparableContents(fileName, contents) {
  if (fileName === "sitemap.xml") {
    return Buffer.from(
      contents.toString().replaceAll(/<lastmod>[^<]*<\/lastmod>/g, "<lastmod></lastmod>"),
    );
  }
  return contents;
}

async function directoriesMatch(leftDirectory, rightDirectory) {
  const [leftEntries, rightEntries] = await Promise.all([
    readdir(leftDirectory, { withFileTypes: true }),
    readdir(rightDirectory, { withFileTypes: true }),
  ]);
  leftEntries.sort((left, right) => left.name.localeCompare(right.name));
  rightEntries.sort((left, right) => left.name.localeCompare(right.name));
  if (leftEntries.length !== rightEntries.length) {
    return false;
  }

  for (let index = 0; index < leftEntries.length; index += 1) {
    const leftEntry = leftEntries[index];
    const rightEntry = rightEntries[index];
    if (
      !leftEntry ||
      !rightEntry ||
      leftEntry.name !== rightEntry.name ||
      leftEntry.isDirectory() !== rightEntry.isDirectory() ||
      leftEntry.isFile() !== rightEntry.isFile()
    ) {
      return false;
    }

    const leftPath = path.join(leftDirectory, leftEntry.name);
    const rightPath = path.join(rightDirectory, rightEntry.name);
    if (leftEntry.isDirectory()) {
      if (!(await directoriesMatch(leftPath, rightPath))) {
        return false;
      }
    } else if (leftEntry.isFile()) {
      const [leftContents, rightContents] = await Promise.all([
        readFile(leftPath),
        readFile(rightPath),
      ]);
      if (
        !comparableContents(leftEntry.name, leftContents).equals(
          comparableContents(rightEntry.name, rightContents),
        )
      ) {
        return false;
      }
    } else {
      return false;
    }
  }
  return true;
}

function redirectPage(destination, canonicalUrl) {
  const serializedDestination = JSON.stringify(destination);
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta http-equiv="refresh" content="0; url=${destination}">
    <meta name="robots" content="noindex">
    <link rel="canonical" href="${canonicalUrl}">
    <title>Zolana TypeScript SDK API reference</title>
    <script>location.replace(${serializedDestination});</script>
  </head>
  <body>
    <p>Continue to the <a href="${destination}">Zolana TypeScript SDK API reference</a>.</p>
  </body>
</html>
`;
}

async function main() {
  const argumentsByName = parseArguments(process.argv.slice(2));
  const siteDirectory = path.resolve(requiredArgument(argumentsByName, "site-dir"));
  const docsDirectory = path.resolve(requiredArgument(argumentsByName, "docs-dir"));
  const publicBaseUrl = requiredArgument(argumentsByName, "public-base-url").replace(/\/+$/, "");
  const version = parseVersion(requiredArgument(argumentsByName, "version"));
  const versionName = `v${version.value}`;
  const sdkDirectory = path.join(siteDirectory, "ts-sdk");
  const versionDirectory = path.join(sdkDirectory, versionName);

  await access(path.join(docsDirectory, "index.html"));
  await mkdir(sdkDirectory, { recursive: true });
  let versionExists = true;
  try {
    await access(versionDirectory);
  } catch (error) {
    if (error?.code === "ENOENT") {
      versionExists = false;
    } else {
      throw error;
    }
  }

  if (versionExists) {
    if (!(await directoriesMatch(docsDirectory, versionDirectory))) {
      throw new Error(`refusing to overwrite published API docs at ${versionDirectory}`);
    }
  } else {
    await cp(docsDirectory, versionDirectory, {
      recursive: true,
      errorOnExist: true,
      force: false,
    });
  }

  const publishedVersions = (await readdir(sdkDirectory, { withFileTypes: true }))
    .filter((entry) => entry.isDirectory() && entry.name.startsWith("v"))
    .map((entry) => parseVersion(entry.name.slice(1)))
    .sort((left, right) => semver.rcompare(left.value, right.value));
  const latest = publishedVersions.find((entry) => entry.prerelease.length === 0);
  if (!latest) {
    throw new Error("publish a stable API documentation version before prerelease versions");
  }

  const latestName = `v${latest.value}`;
  const latestUrl = `${publicBaseUrl}/${latestName}/`;
  await mkdir(path.join(sdkDirectory, "latest"), { recursive: true });
  await writeFile(path.join(siteDirectory, ".nojekyll"), "");
  await writeFile(path.join(siteDirectory, "index.html"), redirectPage("./ts-sdk/", latestUrl));
  await writeFile(
    path.join(sdkDirectory, "index.html"),
    redirectPage(`./${latestName}/`, latestUrl),
  );
  await writeFile(
    path.join(sdkDirectory, "latest", "index.html"),
    redirectPage(`../${latestName}/`, latestUrl),
  );
  await writeFile(
    path.join(sdkDirectory, "versions.json"),
    `${JSON.stringify(
      {
        latest: latestName,
        versions: publishedVersions.map((entry) => ({
          version: `v${entry.value}`,
          url: `${publicBaseUrl}/v${entry.value}/`,
        })),
      },
      null,
      2,
    )}\n`,
  );
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
