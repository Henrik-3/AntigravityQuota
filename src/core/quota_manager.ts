/**
 * Quota Manager Service
 */

import * as https from 'https';
import {quota_snapshot, model_quota_info, prompt_credits_info, server_user_status_response} from '../utils/types';

export class QuotaManager {
	private port: number = 0;
	private csrf_token: string = '';

	private update_callback?: (snapshot: quota_snapshot) => void;
	private error_callback?: (error: Error) => void;
	private polling_timer?: NodeJS.Timeout;

	constructor() {}

	init(port: number, csrf_token: string) {
		this.port = port;
		this.csrf_token = csrf_token;
	}

	private request<T>(path: string, body: object): Promise<T> {
		return new Promise((resolve, reject) => {
			const data = JSON.stringify(body);
			const options: https.RequestOptions = {
				hostname: '127.0.0.1',
				port: this.port,
				path,
				method: 'POST',
				headers: {
					'Content-Type': 'application/json',
					'Content-Length': Buffer.byteLength(data),
					'Connect-Protocol-Version': '1',
					'X-Codeium-Csrf-Token': this.csrf_token,
				},
				rejectUnauthorized: false,
				timeout: 5000,
			};

			const req = https.request(options, res => {
				let body = '';
				res.on('data', chunk => (body += chunk));
				res.on('end', () => {
					try {
						resolve(JSON.parse(body) as T);
					} catch {
						reject(new Error('Invalid JSON response'));
					}
				});
			});

			req.on('error', reject);
			req.on('timeout', () => {
				req.destroy();
				reject(new Error('Request timeout'));
			});

			req.write(data);
			req.end();
		});
	}

	on_update(callback: (snapshot: quota_snapshot) => void) {
		this.update_callback = callback;
	}

	on_error(callback: (error: Error) => void) {
		this.error_callback = callback;
	}

	start_polling(interval_ms: number) {
		this.stop_polling();
		this.fetch_quota();
		this.polling_timer = setInterval(() => this.fetch_quota(), interval_ms);
	}

	stop_polling() {
		if (this.polling_timer) {
			clearInterval(this.polling_timer);
			this.polling_timer = undefined;
		}
	}

	async fetch_quota() {
		try {
			const data = await this.request<server_user_status_response>('/exa.language_server_pb.LanguageServerService/GetUserStatus', {
				metadata: {
					ideName: 'antigravity',
					extensionName: 'antigravity',
					locale: 'en',
				},
			});

			const snapshot = this.parse_response(data);

			if (this.update_callback) {
				this.update_callback(snapshot);
			}
		} catch (error: any) {
			console.error('Quota fetch error:', error.message);
			if (this.error_callback) {
				this.error_callback(error);
			}
		}
	}

	private parse_response(data: server_user_status_response): quota_snapshot {
		const user_status = data.userStatus;
		const plan_info = user_status.planStatus?.planInfo;
		const available_credits = user_status.planStatus?.availablePromptCredits;

		let prompt_credits: prompt_credits_info | undefined;

		if (plan_info && available_credits !== undefined) {
			const monthly = Number(plan_info.monthlyPromptCredits);
			const available = Number(available_credits);
			if (monthly > 0) {
				prompt_credits = {
					available,
					monthly,
					used_percentage: ((monthly - available) / monthly) * 100,
					remaining_percentage: (available / monthly) * 100,
				};
			}
		}

		const raw_models = user_status.cascadeModelConfigData?.clientModelConfigs || [];
		const models: model_quota_info[] = raw_models
			.filter((m: any) => m.quotaInfo)
			.map((m: any) => {
				const reset_time = new Date(m.quotaInfo.resetTime);
				const now = new Date();
				const diff = reset_time.getTime() - now.getTime();

				return {
					label: m.label,
					model_id: m.modelOrAlias?.model || 'unknown',
					remaining_fraction: m.quotaInfo.remainingFraction,
					remaining_percentage: m.quotaInfo.remainingFraction !== undefined ? m.quotaInfo.remainingFraction * 100 : undefined,
					is_exhausted: m.quotaInfo.remainingFraction === 0,
					reset_time: reset_time,
					time_until_reset: diff,
					time_until_reset_formatted: this.format_time(diff, reset_time),
				};
			});

		return {
			timestamp: new Date(),
			prompt_credits,
			models,
		};
	}

	private format_time(ms: number, reset_time: Date): string {
		if (ms <= 0) return 'Ready';
		const mins = Math.ceil(ms / 60000);
		let duration = '';
		if (mins < 60) {
			duration = `${mins}m`;
		} else {
			const hours = Math.floor(mins / 60);
			duration = `${hours}h ${mins % 60}m`;
		}

		const date_str = reset_time.toLocaleDateString(undefined, {
			day: '2-digit',
			month: '2-digit',
			year: 'numeric',
		});
		const time_str = reset_time.toLocaleTimeString(undefined, {
			hour: '2-digit',
			minute: '2-digit',
			hour12: false,
		});

		return `${duration} (${date_str} ${time_str})`;
	}
}
