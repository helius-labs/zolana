// Vite needs the worker entry to be a file inside this app so `?worker` can
// bundle it. The implementation lives in the shared core, which both UIs use.
import "@zolana/poc-core/worker";
