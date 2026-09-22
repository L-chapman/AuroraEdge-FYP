import { describe, expect, it } from 'vitest'
import { onboardingNotice } from './onboardingNotice'

describe('managed-domain onboarding notices', () => {
  it('reports a successfully saved initial grade', () => {
    expect(onboardingNotice('example.com', { grade: 'A', score: 92, severity: 'INFO' })).toEqual({
      tone: 'success',
      message: 'example.com is now monitored with an initial grade of A.',
    })
  })

  it('keeps partial onboarding honest when the scan fails', () => {
    expect(onboardingNotice('example.com', { error: 'internal detail' })).toEqual({
      tone: 'warning',
      message: 'example.com is now monitored, but its initial scan could not be completed. Use Rescan to try again.',
    })
  })

  it('prompts for a baseline when the scanner is unavailable', () => {
    expect(onboardingNotice('example.com')).toEqual({
      tone: 'warning',
      message: 'example.com is now monitored. Run a scan to establish its baseline.',
    })
  })
})
