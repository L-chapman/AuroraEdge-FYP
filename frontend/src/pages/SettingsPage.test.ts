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
    expect(payload.automatic_remediation).toBe('false')
  })

  it('includes a replacement API token when the operator provides one', () => {
    const payload = buildSettingsPayload({ ...settings, cf_api_token: 'replacement-token' })

    expect(payload).toHaveProperty('cf_api_token', 'replacement-token')
  })
})
