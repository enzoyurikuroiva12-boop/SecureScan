export const API = (import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000/api/v1').replace(/\/$/, '')

export type Finding = {
  id: string; tool: string; category: string; severity: string; title: string; description: string
  file?: string | null; line?: number | null; rule?: string | null; remediation?: string | null
  references?: string[]; package?: string | null; version?: string | null; fixed_version?: string | null
  vulnerability_id?: string | null; original_severity?: string | null; evidence?: string | null; confidence?: string | null
  source?: string | null; source_consulted_at?: string | null
  files?: string[]
}
export type ToolResult = { name: string; status: string; version?: string | null; details?: string }
export type Scan = {
  id: string; project_name: string; status: string; created_at: string; started_at?: string | null
  completed_at?: string | null; duration_seconds?: number | null; uploaded_bytes: number; files_examined: number
  finding_count: number; severity_counts: Record<string, number>; findings: Finding[]; tools: ToolResult[]
  warnings: string[]; config: Record<string, boolean>
}

export async function getScans(): Promise<Scan[]> {
  const response = await fetch(`${API}/scans`)
  if (!response.ok) throw new Error('Não foi possível carregar o histórico de análises.')
  return (await response.json()).items
}
export async function getScan(id: string): Promise<Scan> {
  const response = await fetch(`${API}/scans/${id}`)
  if (!response.ok) throw new Error(response.status === 404 ? 'Análise não encontrada.' : 'Não foi possível carregar os resultados.')
  return response.json()
}
export function errorMessage(body: unknown, fallback: string): string {
  if (body && typeof body === 'object' && 'detail' in body) {
    const detail = (body as { detail: unknown }).detail
    if (detail && typeof detail === 'object' && 'message' in detail) return String((detail as { message: unknown }).message)
    if (typeof detail === 'string') return detail
  }
  return fallback
}
