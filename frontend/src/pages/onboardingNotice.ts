export type InitialScan =
  | { grade: string; score: number; severity: string }
  | { error: string }

export function onboardingNotice(
  domain: string,
  initialScan?: InitialScan,
): { tone: 'success' | 'warning'; message: string } {
  if (initialScan && 'grade' in initialScan) {
    return {
      tone: 'success',
      message: `${domain} is now monitored with an initial grade of ${initialScan.grade}.`,
    }
  }
  if (initialScan && 'error' in initialScan) {
    return {
      tone: 'warning',
      message: `${domain} is now monitored, but its initial scan could not be completed. Use Rescan to try again.`,
    }
  }
  return {
    tone: 'warning',
    message: `${domain} is now monitored. Run a scan to establish its baseline.`,
  }
}
