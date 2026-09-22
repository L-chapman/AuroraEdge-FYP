export function buildSettingsPayload<
  T extends {
    cf_api_token: string
    monitoring_enabled: boolean
    automatic_remediation: boolean
  },
>(values: T) {
  const {
    cf_api_token: apiToken,
    monitoring_enabled: monitoringEnabled,
    automatic_remediation: automaticRemediation,
    ...settings
  } = values
  return {
    ...settings,
    monitoring_enabled: String(monitoringEnabled),
    automatic_remediation: String(automaticRemediation),
    ...(apiToken ? { cf_api_token: apiToken } : {}),
  }
}
