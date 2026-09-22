import { zodResolver } from '@hookform/resolvers/zod'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { useForm } from 'react-hook-form'
import { z } from 'zod'
import { ApiError, apiRequest, asBoolean } from '../api/client'
import type { Bootstrap, SettingsResponse } from '../api/types'
import { Button, Card, ConfirmDialog, ErrorState, Field, InlineNotice, LoadingState, PageHeader, StatusBadge } from '../components/ui'
import { buildSettingsPayload } from './settingsPayload'

// Keep validation compatible with our no-eval CSP, including Zod's feature probe.
// This must run before creating an object schema, not only when parsing a form.
z.config({ jitless: true })

const settingsSchema = z.object({
  org_name: z.string().trim().max(120, 'Organisation name must be 120 characters or fewer.'),
  alert_email: z.union([z.literal(''), z.email('Enter a valid email address.')]),
  monitor_interval: z.enum(['6', '12', '24', '48', '168']),
  monitoring_enabled: z.boolean(),
  automatic_remediation: z.boolean(),
  cf_zone_id: z.string().trim().max(80),
  cf_account_id: z.string().trim().max(80),
  cf_api_token: z.string().max(512),
})

type SettingsForm = z.infer<typeof settingsSchema>

function settingString(settings: Record<string, string | boolean | number>, key: string): string {
  return String(settings[key] ?? '')
}

export function SettingsPage() {
  const settingsQuery = useQuery({ queryKey: ['settings'], queryFn: ({ signal }) => apiRequest<SettingsResponse>('/api/settings', { signal }) })
  const bootstrapQuery = useQuery({ queryKey: ['bootstrap'], queryFn: ({ signal }) => apiRequest<Bootstrap>('/api/v1/bootstrap', { signal }) })
  const retry = () => { void Promise.all([settingsQuery.refetch(), bootstrapQuery.refetch()]) }

  // Mount the editor only when both initial responses exist. Rendering blank
  // controls and resetting them in an effect can interrupt the first edit.
  if (!settingsQuery.data || !bootstrapQuery.data) {
    if (settingsQuery.isLoading || bootstrapQuery.isLoading) return <LoadingState label="Loading configuration" />
    return <ErrorState message="Settings and runtime security mode could not be loaded safely." action={<Button onClick={retry}>Try again</Button>} />
  }

  return <SettingsEditor settings={settingsQuery.data.settings} production={bootstrapQuery.data.runtime.production} unavailable={settingsQuery.isError || bootstrapQuery.isError} onRetry={retry} />
}

function SettingsEditor({ settings, production, unavailable, onRetry }: {
  settings: SettingsResponse['settings']
  production: boolean
  unavailable: boolean
  onRetry: () => void
}) {
  const [clearOpen, setClearOpen] = useState(false)
  const [message, setMessage] = useState('')
  const [saving, setSaving] = useState(false)
  const [cloudflareResult, setCloudflareResult] = useState<{ ok: boolean; message: string; zone_name?: string; permissions?: Record<string, boolean> } | null>(null)
  const queryClient = useQueryClient()
  const form = useForm<SettingsForm>({
    resolver: zodResolver(settingsSchema),
    disabled: saving || unavailable,
    // React Hook Form caches these defaults at mount. A background refresh
    // must never reset a draft, move the caret, or replace selected text.
    defaultValues: {
      org_name: settingString(settings, 'org_name'),
      alert_email: settingString(settings, 'alert_email'),
      monitor_interval: (['6', '12', '24', '48', '168'].includes(settingString(settings, 'monitor_interval')) ? settingString(settings, 'monitor_interval') : '24') as SettingsForm['monitor_interval'],
      monitoring_enabled: asBoolean(settings.monitoring_enabled),
      automatic_remediation: asBoolean(settings.automatic_remediation),
      cf_zone_id: settingString(settings, 'cf_zone_id'),
      cf_account_id: settingString(settings, 'cf_account_id'),
      cf_api_token: '',
    },
  })

  const save = useMutation({
    onMutate: () => { setSaving(true) },
    mutationFn: (values: SettingsForm) => apiRequest<{ ok: boolean; saved: string[] }>('/api/settings', {
      method: 'POST',
      body: buildSettingsPayload(values),
    }),
    onSuccess: async (result, values) => {
      setCloudflareResult(null)
      setMessage(`Saved ${result.saved.length} setting${result.saved.length === 1 ? '' : 's'}.`)
      // The server confirmed this submission. Use it as the new clean baseline
      // and clear the write-only token without waiting for another read.
      form.reset({ ...values, cf_api_token: '' })
      await Promise.all([queryClient.invalidateQueries({ queryKey: ['settings'] }), queryClient.invalidateQueries({ queryKey: ['dashboard'] }), queryClient.invalidateQueries({ queryKey: ['bootstrap'] })])
    },
    onSettled: () => { setSaving(false) },
  })

  const testCloudflare = useMutation({
    mutationFn: () => apiRequest<{ ok: boolean; message: string; zone_name?: string; permissions?: Record<string, boolean> }>('/api/settings/test-cloudflare', { method: 'POST' }),
    onSuccess: setCloudflareResult,
  })

  const clearData = useMutation({
    mutationFn: () => apiRequest<{ message: string }>('/api/data/clear', { method: 'POST' }),
    onSuccess: async (result) => {
      setClearOpen(false)
      setMessage(result.message)
      await queryClient.invalidateQueries()
    },
  })

  const configured = asBoolean(settings.cf_api_token_configured)
  const mutationError = save.error ?? testCloudflare.error ?? clearData.error

  return (
    <div className="page-stack">
      <PageHeader eyebrow="Make it yours" title="Settings" description="Choose when your domains are checked, connect optional services, and manage your workspace data." />
      {unavailable ? <InlineNotice tone="warning">Settings could not be refreshed safely. Your draft is preserved; reload the saved settings before making changes. <Button type="button" variant="ghost" onClick={onRetry}>Retry settings</Button></InlineNotice> : null}
      {message ? <InlineNotice tone="success">{message}</InlineNotice> : null}
      {mutationError ? <InlineNotice tone="danger">{mutationError instanceof ApiError ? mutationError.detail : 'The operation failed.'}</InlineNotice> : null}
      <form className="page-stack" onSubmit={form.handleSubmit((values) => save.mutate(values))} noValidate>
        <Card>
          <div className="section-heading"><div><p className="eyebrow">Workspace</p><h2>Organisation</h2></div></div>
          <div className="form-grid">
            <Field label="Organisation name" htmlFor="org-name" error={form.formState.errors.org_name?.message}>
              <input id="org-name" {...form.register('org_name')} />
            </Field>
            <Field label="Alert email" htmlFor="alert-email" hint="Reserved for deployment-level notification integrations." error={form.formState.errors.alert_email?.message}>
              <input id="alert-email" type="email" autoComplete="email" {...form.register('alert_email')} />
            </Field>
          </div>
        </Card>

        <Card>
          <div className="section-heading"><div><p className="eyebrow">Automation</p><h2>Monitoring</h2></div></div>
          <div className="form-grid">
            <Field label="Scan interval" htmlFor="monitor-interval">
              <select id="monitor-interval" {...form.register('monitor_interval')}><option value="6">Every 6 hours</option><option value="12">Every 12 hours</option><option value="24">Every 24 hours</option><option value="48">Every 48 hours</option><option value="168">Weekly</option></select>
            </Field>
            <div className="toggle-stack">
              <label className="toggle"><input type="checkbox" {...form.register('monitoring_enabled')} /><span><strong>Continuous monitoring</strong><small>Periodically rescan managed domains.</small></span></label>
              <label className="toggle toggle--danger"><input type="checkbox" {...form.register('automatic_remediation')} /><span><strong>Automatic remediation</strong><small>High risk: may change authorised Cloudflare DNS records after drift.</small></span></label>
            </div>
          </div>
        </Card>

        <Card>
          <div className="section-heading"><div><p className="eyebrow">Optional integration</p><h2>Cloudflare DNS</h2></div><StatusBadge value={configured ? 'Credential configured' : 'Not configured'} /></div>
          {production ? <InlineNotice tone="info">Production secrets are environment-only. Set <code>CF_API_TOKEN</code> on the server; NorthFlux will never return it here.</InlineNotice> : null}
          <div className="form-grid">
            <Field label="Zone ID" htmlFor="cf-zone"><input id="cf-zone" autoComplete="off" {...form.register('cf_zone_id')} /></Field>
            <Field label="Account ID" htmlFor="cf-account"><input id="cf-account" autoComplete="off" {...form.register('cf_account_id')} /></Field>
            {!production ? <Field label="API token" htmlFor="cf-token" hint="The current token is never displayed. Leave blank to keep it unchanged."><input id="cf-token" type="password" autoComplete="new-password" {...form.register('cf_api_token')} /></Field> : null}
          </div>
          <div className="button-row"><Button type="button" variant="secondary" disabled={testCloudflare.isPending || unavailable || save.isPending} onClick={() => { setCloudflareResult(null); testCloudflare.mutate() }}>{testCloudflare.isPending ? 'Testing saved configuration…' : 'Test saved connection'}</Button></div>
          {cloudflareResult ? <InlineNotice tone={cloudflareResult.ok ? 'success' : 'warning'}><strong>{cloudflareResult.ok ? 'Connection verified.' : 'Connection unavailable.'}</strong> {cloudflareResult.message}{cloudflareResult.zone_name ? ` Zone: ${cloudflareResult.zone_name}.` : ''}</InlineNotice> : null}
        </Card>

        <div className="sticky-actions"><Button type="submit" disabled={save.isPending || unavailable || !form.formState.isDirty}>{save.isPending ? 'Saving…' : 'Save settings'}</Button><span aria-live="polite">{form.formState.isDirty ? 'Unsaved changes' : 'No unsaved edits'}</span></div>
      </form>

      <Card className="danger-zone">
        <div><p className="eyebrow">Danger zone</p><h2>Delete operational data</h2><p>Remove scan history, managed domains, and alerts while preserving configuration.</p></div>
        <Button variant="danger" type="button" disabled={unavailable || save.isPending} onClick={() => setClearOpen(true)}>Clear all scan data</Button>
      </Card>
      <ConfirmDialog open={clearOpen} title="Clear all NorthFlux scan data?" description="This permanently deletes results, history, managed domains, alerts, and generated reports. Settings and audit logs remain. This cannot be undone." confirmLabel="Permanently clear data" error={clearData.error instanceof ApiError ? clearData.error.detail : clearData.error ? 'Scan data could not be cleared.' : undefined} dangerous busy={clearData.isPending} onCancel={() => { if (!clearData.isPending) setClearOpen(false) }} onConfirm={() => clearData.mutate()} />
    </div>
  )
}
