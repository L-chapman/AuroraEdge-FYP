import { cloneElement, forwardRef, isValidElement, useEffect, useId, useRef } from 'react'
import type { ButtonHTMLAttributes, PropsWithChildren, ReactNode } from 'react'

export function Card({ children, className = '' }: PropsWithChildren<{ className?: string }>) {
  return <section className={`card ${className}`.trim()}>{children}</section>
}

export const Button = forwardRef<HTMLButtonElement, PropsWithChildren<ButtonHTMLAttributes<HTMLButtonElement> & { variant?: 'primary' | 'secondary' | 'danger' | 'ghost' }>>(function Button({
  children,
  className = '',
  variant = 'primary',
  ...props
}, ref) {
  return (
    <button ref={ref} className={`button button--${variant} ${className}`.trim()} {...props}>
      {children}
    </button>
  )
})

export function PageHeader({ eyebrow, title, description, actions }: {
  eyebrow?: string
  title: string
  description?: string
  actions?: ReactNode
}) {
  return (
    <header className="page-header">
      <div>
        {eyebrow ? <p className="eyebrow">{eyebrow}</p> : null}
        <h1>{title}</h1>
        {description ? <p className="page-header__description">{description}</p> : null}
      </div>
      {actions ? <div className="page-header__actions">{actions}</div> : null}
    </header>
  )
}

export function StatusBadge({ value }: { value: string | number | null | undefined }) {
  const label = String(value ?? 'Unknown')
  const tone = label.toLowerCase().replace(/[^a-z0-9]+/g, '-')
  return <span className={`status-badge status-badge--${tone}`}>{label}</span>
}

export function Metric({ label, value, detail }: { label: string; value: ReactNode; detail?: string }) {
  return (
    <Card className="metric">
      <p className="metric__label">{label}</p>
      <p className="metric__value">{value}</p>
      {detail ? <p className="metric__detail">{detail}</p> : null}
    </Card>
  )
}

export function LoadingState({ label = 'Loading', fullPage = false }: { label?: string; fullPage?: boolean }) {
  return (
    <div className={`loading-state ${fullPage ? 'loading-state--page' : ''}`} role="status" aria-live="polite">
      <span className="spinner" aria-hidden="true" />
      <span>{label}…</span>
    </div>
  )
}

export function EmptyState({ title, description, action }: { title: string; description: string; action?: ReactNode }) {
  return (
    <div className="empty-state">
      <span className="empty-state__icon" aria-hidden="true">◇</span>
      <h2>{title}</h2>
      <p>{description}</p>
      {action}
    </div>
  )
}

export function ErrorState({ title = 'Something went wrong', message, action }: { title?: string; message: string; action?: ReactNode }) {
  return (
    <div className="error-state" role="alert">
      <h2>{title}</h2>
      <p>{message}</p>
      {action}
    </div>
  )
}

export function Field({ label, htmlFor, hint, error, children }: {
  label: string
  htmlFor: string
  hint?: string
  error?: string
  children: ReactNode
}) {
  const hintId = useId()
  const errorId = useId()
  const control = isValidElement<{
    'aria-describedby'?: string
    'aria-invalid'?: boolean | 'false' | 'grammar' | 'spelling' | 'true'
  }>(children)
    ? cloneElement(children, {
        'aria-describedby': [
          children.props['aria-describedby'],
          hint ? hintId : undefined,
          error ? errorId : undefined,
        ].filter(Boolean).join(' ') || undefined,
        'aria-invalid': error ? true : children.props['aria-invalid'],
      })
    : children

  return (
    <div className="field">
      <label htmlFor={htmlFor}>{label}</label>
      {control}
      {hint ? <p className="field__hint" id={hintId}>{hint}</p> : null}
      {error ? <p className="field__error" id={errorId} role="alert">{error}</p> : null}
    </div>
  )
}

export function InlineNotice({ tone = 'info', children }: PropsWithChildren<{ tone?: 'info' | 'success' | 'warning' | 'danger' }>) {
  return <div className={`notice notice--${tone}`} role={tone === 'danger' ? 'alert' : 'status'}>{children}</div>
}

export function ConfirmDialog({ open, title, description, confirmLabel, error, dangerous = false, busy = false, onConfirm, onCancel }: {
  open: boolean
  title: string
  description: string
  confirmLabel: string
  error?: string
  dangerous?: boolean
  busy?: boolean
  onConfirm: () => void
  onCancel: () => void
}) {
  const dialogRef = useRef<HTMLDialogElement>(null)
  const cancelRef = useRef<HTMLButtonElement>(null)

  useEffect(() => {
    const dialog = dialogRef.current
    if (!dialog) return
    if (open && !dialog.open) {
      dialog.showModal()
      cancelRef.current?.focus()
    } else if (!open && dialog.open) {
      dialog.close()
    }
  }, [open])

  if (!open) return null

  return (
    <dialog
      ref={dialogRef}
      className="dialog"
      aria-labelledby="confirmation-title"
      onCancel={(event) => {
        event.preventDefault()
        if (!busy) onCancel()
      }}
      onClose={() => {
        if (open && !busy) onCancel()
      }}
    >
      <div className="dialog__body">
        <p className="eyebrow">Confirmation required</p>
        <h2 id="confirmation-title">{title}</h2>
        <p>{description}</p>
        {error ? <InlineNotice tone="danger">{error}</InlineNotice> : null}
      </div>
      <div className="dialog__actions">
        <Button ref={cancelRef} type="button" variant="secondary" disabled={busy} onClick={onCancel}>Cancel</Button>
        <Button type="button" variant={dangerous ? 'danger' : 'primary'} disabled={busy} onClick={onConfirm}>
          {busy ? 'Working…' : confirmLabel}
        </Button>
      </div>
    </dialog>
  )
}
