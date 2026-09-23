import { Link } from 'react-router-dom'
import type { RemediationResponse } from '../api/types'
import { InlineNotice } from './ui'

export function RemediationOutcome({ result }: { result: RemediationResponse }) {
  const applied = result.applied ?? []
  const failed = result.failed ?? []
  const manual = result.manual_actions ?? []
  const manualReview = result.status === 'manual_review' && !applied.length && !failed.length
  const regressed = typeof result.score === 'number' && typeof result.pre_fix_score === 'number' && result.score < result.pre_fix_score
  const confirmed = result.status === 'success' && result.verification_status === 'observed' && !failed.length && !manual.length && !regressed
  const tone = confirmed ? 'success' : failed.length && !applied.length ? 'danger' : manualReview || result.status === 'no_action' ? 'info' : 'warning'
  const summary = confirmed ? 'Changes submitted and a follow-up scan completed.'
    : manualReview ? 'Manual review is required before making these DNS changes. No automatic changes were attempted.'
      : result.status === 'no_action' ? 'No automatic changes were needed.'
      : applied.length ? 'Some DNS changes were submitted. Review the outcome before making further changes.'
        : 'No automatic changes were completed. Review the reasons and any manual steps below.'

  return (
    <section className="card form-stack" aria-label={`DNS change outcome for ${result.domain}`}>
      <h2>DNS change outcome for {result.domain}</h2>
      <InlineNotice tone={tone}>{summary}</InlineNotice>
      {result.verification?.trim() ? <p>{result.verification}</p> : null}
      {regressed ? <InlineNotice tone="warning">The follow-up score is lower than before the change. Review the new findings before continuing.</InlineNotice> : null}
      {applied.length ? <div><h3>Submitted changes</h3><ul>{applied.map((item, index) => <li key={`${item.type}-${index}`}><strong>{item.type}</strong>{item.message ? <p>{item.message}</p> : null}</li>)}</ul></div> : null}
      {failed.length ? <div><h3>Changes not completed</h3><ul>{failed.map((item, index) => <li key={`${item.type}-${index}`}><strong>{item.type}</strong>{item.message ? <p>{item.message}</p> : null}</li>)}</ul></div> : null}
      {manual.length ? <div><h3>Manual review required</h3><ul>{manual.map((item, index) => <li key={`${item.type}-${index}`}><strong>{item.type}</strong>{item.description ? <p>{item.description}</p> : null}{item.recommended ? <p>{item.recommended}</p> : null}{item.steps ? <p>{item.steps}</p> : null}</li>)}</ul></div> : null}
      {applied.length ? <p>The earlier scan predates these changes. Run a fresh scan before relying on a grade.</p> : null}
      {result.history_saved ? <Link className="button button--secondary" to={`/domain/${encodeURIComponent(result.domain)}`}>Review saved verification</Link> : null}
    </section>
  )
}
