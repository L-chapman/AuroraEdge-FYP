import { InlineNotice } from './ui'

export function IncompleteScanNotice({ notes }: { notes?: unknown }) {
  const detail = Array.isArray(notes) ? notes.map(String).join(' ') : String(notes ?? '')
  return (
    <InlineNotice tone="warning">
      <strong>This scan is incomplete.</strong> Some checks could not finish, so no overall grade is shown. Retry the scan before applying DNS changes.
      {detail ? <p>{detail}</p> : null}
    </InlineNotice>
  )
}
