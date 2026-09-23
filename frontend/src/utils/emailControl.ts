import { asBoolean } from '../api/client'

/** Record presence is not a complete policy assessment; Null MX is intentional. */
export function emailControlStatus(evidence: Record<string, unknown>, field: string, missingLabel = 'Not found') {
  if (asBoolean(evidence.null_mx)) {
    if (field === 'mx_present') return { label: 'No incoming mail', tone: '', marker: '—' }
    if (field === 'mta_sts_present' || field === 'tls_rpt_present') return { label: 'Not applicable', tone: '', marker: '—' }
  }
  if (asBoolean(evidence[field])) return { label: 'Record found', tone: '--pass', marker: '✓' }
  if (asBoolean(evidence.scan_incomplete)) return { label: 'Not confirmed', tone: '', marker: '?' }
  return { label: missingLabel, tone: '--fail', marker: '!' }
}
