import { Link } from 'react-router-dom'

export function NotFoundPage() {
  return (
    <div className="not-found">
      <p className="not-found__code">404</p>
      <h1>That page is outside the flux.</h1>
      <p>The address may have changed, or the page may no longer exist.</p>
      <Link className="button button--primary" to="/">Return to overview</Link>
    </div>
  )
}
