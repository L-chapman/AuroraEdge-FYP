export type InitialScan =
  | { grade: string; score: number; severity: string; scan_incomplete?: boolean }
  | { error: string; scan_incomplete?: boolean }

export function onboardingNotice(
  domain: string,
  initialScan?: InitialScan,
): { tone: 'success' | 'warning'; message: string } {
  if (initialScan?.scan_incomplete) {
    return { tone: 'warning', message: `${domain} is now managed, but its initial scan was incomplete. No grade has been assigned. Use Rescan to try again.` }
  }
  if (initialScan && 'grade' in initialScan) {
    return {
      tone: 'success',
      message: `${domain} is now managed with an initial grade of ${initialScan.grade}.`,
    }
  }
  if (initialScan && 'error' in initialScan) {
    return {
      tone: 'warning',
      message: `${domain} is now managed, but its initial scan could not be completed. Use Rescan to try again.`,
    }
  }
  return {
    tone: 'warning',
    message: `${domain} is now managed. Run a scan to establish its baseline.`,
  }
}
