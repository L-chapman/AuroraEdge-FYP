import { describe, expect, it } from 'vitest'
import { emailControlStatus } from './emailControl'

describe('Scoped email-control labels', () => {
  it.each([
    [{ null_mx: true }, 'mx_present', 'No incoming mail', ''],
    [{ null_mx: 1 }, 'mta_sts_present', 'Not applicable', ''],
    [{ null_mx: true }, 'tls_rpt_present', 'Not applicable', ''],
    [{ null_mx: true, spf_present: false }, 'spf_present', 'Not found', '--fail'],
    [{ scan_incomplete: true, spf_present: true }, 'spf_present', 'Record found', '--pass'],
    [{ scan_incomplete: true }, 'spf_present', 'Not confirmed', ''],
    [{ spf_present: false }, 'spf_present', 'Not found', '--fail'],
  ] as const)('labels %j / %s without confusing inbound and outbound coverage', (evidence, field, label, tone) => {
    expect(emailControlStatus(evidence, field)).toMatchObject({ label, tone })
  })
  it('supports a scan-specific missing-record explanation', () => {
    expect(emailControlStatus({}, 'spf_present', 'Needs attention').label).toBe('Needs attention')
  })
})
