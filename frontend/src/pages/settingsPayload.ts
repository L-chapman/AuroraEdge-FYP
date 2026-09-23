export function buildSettingsPayload<
  T extends {
    org_name: string
    monitor_interval: string
    cf_api_token: string
    cf_zone_id: string
    cf_account_id: string
    monitoring_enabled: boolean
  },
>(values: T) {
  // Only submit active controls. Omitted compatibility settings stay untouched
  // on the server, including legacy values unknown to this version of the UI.
  return {
    org_name: values.org_name,
    monitor_interval: values.monitor_interval,
    monitoring_enabled: String(values.monitoring_enabled),
    cf_zone_id: values.cf_zone_id,
    cf_account_id: values.cf_account_id,
    ...(values.cf_api_token ? { cf_api_token: values.cf_api_token } : {}),
  }
}
