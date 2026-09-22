/** A local, decorative mark: no downloaded assets or third-party font required. */
export function BrandMark({ className = '' }: { className?: string }) {
  return (
    <span className={`brand-mark ${className}`.trim()} aria-hidden="true">
      <svg viewBox="0 0 40 40" fill="none" focusable="false">
        <path d="M10 29V11l20 18V11" stroke="currentColor" strokeWidth="3.5" strokeLinecap="round" strokeLinejoin="round" />
        <path d="m24 11 6-5 6 5" stroke="currentColor" strokeWidth="3.5" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
    </span>
  )
}
