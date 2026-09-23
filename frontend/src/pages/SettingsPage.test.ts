import { describe, expect, it } from 'vitest'
import { buildSettingsPayload } from './settingsPayload'

const settings = {
  org_name: 'NorthFlux Test Operator',
  alert_email: 'alerts@example.com',
  monitor_interval: '24' as const,
  monitoring_enabled: true,
  automatic_remediation: false,
  cf_zone_id: 'zone-id',
  cf_account_id: 'account-id',
}

describe('buildSettingsPayload', () => {
  it('omits a blank API token so the stored credential remains unchanged', () => {
    const payload = buildSettingsPayload({ ...settings, cf_api_token: '' })

    expect(payload).not.toHaveProperty('cf_api_token')
    expect(payload.monitoring_enabled).toBe('true')
    expect(payload).not.toHaveProperty('automatic_remediation')
    expect(payload).not.toHaveProperty('alert_email')
  })

  it('includes a replacement API token when the operator provides one', () => {
    const payload = buildSettingsPayload({ ...settings, cf_api_token: 'replacement-token' })

    expect(payload).toHaveProperty('cf_api_token', 'replacement-token')
  })

  it.each([true, false])('leaves retained compatibility settings unchanged when the old preference is %s', (automaticRemediation) => {
    const payload = buildSettingsPayload({
      ...settings,
      cf_api_token: '',
      monitoring_enabled: false,
      automatic_remediation: automaticRemediation,
      alert_email: 'legacy contact value, not a valid email',
      future_setting: 'must not be submitted by an older editor',
    })

    expect(payload).toEqual({
      org_name: settings.org_name,
      monitor_interval: settings.monitor_interval,
      monitoring_enabled: 'false',
      cf_zone_id: settings.cf_zone_id,
      cf_account_id: settings.cf_account_id,
    })
  })
})
