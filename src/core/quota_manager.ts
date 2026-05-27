/**
 * Quota Manager Service
 */

import * as https from 'https';
import {quota_snapshot, model_quota_info, prompt_credits_info, server_user_status_response} from '../utils/types';
import {logger} from '../utils/logger';

export const RECONNECT_REQUIRED = 'RECONNECT_REQUIRED';

export class QuotaManager {
	private port: number = 0;
	private csrf_token: string = '';

	private update_callback?: (snapshot: quota_snapshot) => void;
	private error_callback?: (error: Error) => void;
	private polling_timer?: NodeJS.Timeout;
	private consecutive_errors = 0;
	private readonly MAX_CONSECUTIVE_ERRORS = 3;

	constructor() {}

	init(port: number, csrf_token: string) {
		this.port = port;
		this.csrf_token = csrf_token;
		this.consecutive_errors = 0;
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
			this.consecutive_errors = 0;

			if (this.update_callback) {
				this.update_callback(snapshot);
			}
		} catch (error: any) {
			this.consecutive_errors++;
			logger.error(
				'QuotaManager',
				`Fetch failed (${this.consecutive_errors}/${this.MAX_CONSECUTIVE_ERRORS}): ${error.message}`
			);

			if (this.consecutive_errors >= this.MAX_CONSECUTIVE_ERRORS) {
				this.consecutive_errors = 0;
				if (this.error_callback) {
					logger.warn('QuotaManager', 'Triggering reconnect after consecutive failures', error);
					this.error_callback(new Error(RECONNECT_REQUIRED));
				}
			} else if (this.error_callback) {
				this.error_callback(error);
			}
		}
	}

	private get_quota_info(model: any): any | undefined {
		return model.quotaInfo ?? model.quota_info;
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

		logger.debug('QuotaManager', 'Raw model configs:', {
			total: raw_models.length,
			with_quota: raw_models.filter((m: any) => this.get_quota_info(m)).length,
			models: raw_models.map((m: any) => ({
				label: m.label,
				model_id: m.modelOrAlias?.model ?? m.model_or_alias?.model,
				has_quota: !!this.get_quota_info(m),
			})),
		});

		const models_without_quota = raw_models.filter((m: any) => !this.get_quota_info(m));
		if (models_without_quota.length > 0) {
			logger.warn(
				'QuotaManager',
				`${models_without_quota.length} model(s) missing quota info:`,
				models_without_quota.map((m: any) => m.label)
			);
		}

		const models: model_quota_info[] = raw_models.map((m: any) => {
			const quota_info = this.get_quota_info(m);
			const reset_time_raw = quota_info?.resetTime ?? quota_info?.reset_time;
			const reset_time = reset_time_raw ? new Date(reset_time_raw) : new Date(0);
			const now = new Date();
			const diff = reset_time.getTime() - now.getTime();
			const remaining_fraction = quota_info?.remainingFraction ?? quota_info?.remaining_fraction;

			return {
				label: m.label,
				model_id: m.modelOrAlias?.model ?? m.model_or_alias?.model ?? 'unknown',
				remaining_fraction,
				remaining_percentage: remaining_fraction !== undefined ? remaining_fraction * 100 : undefined,
				is_exhausted: remaining_fraction === 0,
				reset_time: reset_time,
				time_until_reset: quota_info ? diff : 0,
				time_until_reset_formatted: quota_info ? this.format_time(diff, reset_time) : 'Unknown',
			};
		});

		models.sort((a, b) => a.label.localeCompare(b.label));
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
