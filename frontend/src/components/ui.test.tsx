import { cleanup, render, screen } from '@testing-library/react'
import { afterEach, describe, expect, it } from 'vitest'
import { Field } from './ui'

afterEach(cleanup)

describe('Field accessibility metadata', () => {
  it('connects its hint and error to the child control', () => {
    render(
      <Field label="Domain" htmlFor="domain" hint="Enter a public domain." error="Domain is required.">
        <input id="domain" />
      </Field>,
    )

    const control = screen.getByLabelText('Domain')
    const hint = screen.getByText('Enter a public domain.')
    const error = screen.getByRole('alert')

    expect(control).toHaveAttribute('aria-describedby', `${hint.id} ${error.id}`)
    expect(control).toHaveAttribute('aria-invalid', 'true')
  })

  it('preserves accessibility metadata already supplied by the child', () => {
    render(
      <>
        <p id="external-description">External context.</p>
        <Field label="Domain" htmlFor="domain" hint="Enter a public domain.">
          <input id="domain" aria-describedby="external-description" aria-invalid="spelling" />
        </Field>
      </>,
    )

    const control = screen.getByLabelText('Domain')
    const hint = screen.getByText('Enter a public domain.')

    expect(control).toHaveAttribute('aria-describedby', `external-description ${hint.id}`)
    expect(control).toHaveAttribute('aria-invalid', 'spelling')
  })
})
