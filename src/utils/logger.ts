/**
 * 構造化ログ出力のシンプルなロガー。
 * 書籍の題材としてシンプルさを優先し、外部ライブラリは使用しない。
 */

type LogLevel = "debug" | "info" | "warn" | "error";

function formatLog(level: LogLevel, message: string, data?: Record<string, unknown>): string {
	const timestamp = new Date().toISOString();
	const entry = {
		timestamp,
		level,
		message,
		...data,
	};
	return JSON.stringify(entry);
}

export const logger = {
	debug(message: string, data?: Record<string, unknown>): void {
		console.debug(formatLog("debug", message, data));
	},

	info(message: string, data?: Record<string, unknown>): void {
		console.info(formatLog("info", message, data));
	},

	warn(message: string, data?: Record<string, unknown>): void {
		console.warn(formatLog("warn", message, data));
	},

	error(message: string, data?: Record<string, unknown>): void {
		console.error(formatLog("error", message, data));
	},
};
