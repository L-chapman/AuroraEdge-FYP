import { cleanup, render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, describe, expect, it } from 'vitest'
import { PrivacyPage } from './PrivacyPage'

afterEach(cleanup)

describe('PrivacyPage capability explanations', () => {
  it('explains manual DNS review, in-app-only notifications and local credential storage', () => {
    render(<MemoryRouter><PrivacyPage /></MemoryRouter>)
    expect(screen.getByText(/Current recommendations require manual review and do not change DNS/)).toBeVisible()
    expect(screen.getByText(/Outbound email delivery is not implemented/)).toBeVisible()
    expect(screen.getByText(/Local development can store provider credentials as plain text in SQLite/)).toBeVisible()
    expect(screen.queryByText(/enable automatic changes/)).not.toBeInTheDocument()
  })
})
