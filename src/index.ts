import { serve } from "@hono/node-server";
import "dotenv/config";
import app from "./app.js";
import { serverConfig } from "./config/server.js";

const { port, host } = serverConfig;

console.log(`認可サーバーを起動します: http://${host}:${port}`);

serve({
	fetch: app.fetch,
	port,
	hostname: host,
});
