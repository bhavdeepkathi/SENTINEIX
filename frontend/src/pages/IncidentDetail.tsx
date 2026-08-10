import { useEffect, useState } from 'react'
import { useParams, Link } from 'react-router-dom'
import api from '../services/api'
import {
  FileText, AlertTriangle, Clock, CheckCircle, Brain, Network, Download, ChevronRight, Activity, ShieldAlert
} from 'lucide-react'

interface Incident {
  id: number
  title: string
  description: string | null
  severity: string
  status: string
  risk_score: number
  created_at: string
  updated_at: string
}

interface TimelineEvent {
  sequence_no: number
  timestamp: string
  source: string
  event_type: string
  username: string | null
  source_ip: string | null
  hostname: string | null
  action: string | null
  status: string | null
  severity: string | null
}

interface Alert {
  id: number
  title: string
  description: string | null
  severity: string
  status: string
  created_at: string
}

interface Evidence {
  id: number
  filename: string
  file_type: string | null
  file_size: number | null
  sha256: string
  uploaded_by: number
  uploaded_at: string
  description: string | null
}

interface Investigation {
  id: number
  summary: string | null
  attack_type: string | null
  attack_sequence: string
  root_cause: string | null
  affected_assets: string
  confidence: number | null
  mitre_techniques: string
  created_at: string
}

interface Recommendation {
  id: number
  description: string
  priority: string | null
  is_ai_generated: boolean
}

interface MitreTechnique {
  technique_id: string
  name: string
  tactic: string | null
  confidence: number
  evidence_ref: string | null
}

type Tab = 'overview' | 'timeline' | 'alerts' | 'evidence' | 'ai' | 'mitre' | 'recommendations' | 'report'

export default function IncidentDetail() {
  const { id } = useParams<{ id: string }>()
  const incidentId = Number(id)
  const [incident, setIncident] = useState<Incident | null>(null)
  const [timeline, setTimeline] = useState<TimelineEvent[]>([])
  const [alerts, setAlerts] = useState<Alert[]>([])
  const [evidence, setEvidence] = useState<Evidence[]>([])
  const [investigation, setInvestigation] = useState<Investigation | null>(null)
  const [recommendations, setRecommendations] = useState<Recommendation[]>([])
  const [mitre, setMitre] = useState<MitreTechnique[]>([])
  const [activeTab, setActiveTab] = useState<Tab>('overview')
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  useEffect(() => {
    const fetchAll = async () => {
      try {
        const incRes = (await api.get(`/incidents/${incidentId}`)) as Incident
        const tlRes = (await api.get(`/incidents/${incidentId}/timeline`)) as { timeline: TimelineEvent[] }
        const alRes = (await api.get(`/alerts?incident_id=${incidentId}`)) as Alert[]
        const evRes = (await api.get(`/evidence?incident_id=${incidentId}`)) as Evidence[]
        const mitreRes = (await api.get(`/incidents/${incidentId}/mitre`)) as MitreTechnique[]
        setIncident(incRes)
        setTimeline(tlRes.timeline || [])
        setAlerts(alRes || [])
        setEvidence(evRes || [])
        setMitre(mitreRes || [])

        // fetch investigation separately, ignore 404
        try {
          const invRes = (await api.get(`/incidents/${incidentId}/investigation`)) as Investigation
          setInvestigation(invRes)
          if (invRes?.id) {
            const recRes = (await api.get(`/investigations/${invRes.id}/recommendations`)) as Recommendation[]
            setRecommendations(recRes || [])
          }
        } catch (e: any) {
          if (e.response?.status !== 404) {
            console.warn('Failed to load investigation', e)
          }
          setInvestigation(null)
        }
      } catch (e: any) {
        setError(e.response?.data?.detail || 'Failed to load incident')
      } finally {
        setLoading(false)
      }
    }
    fetchAll()
  }, [incidentId])

  if (loading) return <div className="flex items-center justify-center h-64">Loading...</div>
  if (error) return <div className="text-red-600 text-center p-8">{error}</div>
  if (!incident) return <div className="text-center p-8">Incident not found</div>

  const severityColors: Record<string, string> = {
    critical: 'bg-red-100 text-red-800',
    high: 'bg-orange-100 text-orange-800',
    medium: 'bg-yellow-100 text-yellow-800',
    low: 'bg-green-100 text-green-800',
  }

  const statusIcons: Record<string, React.ReactNode> = {
    open: <AlertTriangle className="w-5 h-5 text-yellow-600" />,
    investigating: <Clock className="w-5 h-5 text-blue-600" />,
    closed: <CheckCircle className="w-5 h-5 text-green-600" />,
  }

  const tabs: { id: Tab; label: string; icon: React.ReactNode }[] = [
    { id: 'overview', label: 'Overview', icon: <FileText className="w-4 h-4" /> },
    { id: 'timeline', label: 'Timeline', icon: <Activity className="w-4 h-4" /> },
    { id: 'alerts', label: 'Alerts', icon: <AlertTriangle className="w-4 h-4" /> },
    { id: 'evidence', label: 'Evidence', icon: <ShieldAlert className="w-4 h-4" /> },
    { id: 'ai', label: 'AI Investigation', icon: <Brain className="w-4 h-4" /> },
    { id: 'mitre', label: 'MITRE ATT&CK', icon: <Network className="w-4 h-4" /> },
    { id: 'recommendations', label: 'Recommendations', icon: <Download className="w-4 h-4" /> },
    { id: 'report', label: 'Report', icon: <ChevronRight className="w-4 h-4" /> },
  ]

  // Helper to safely parse JSON arrays
  const parseJsonArray = (value: string | null): string[] => {
    try {
      return JSON.parse(value || '[]')
    } catch {
      return []
    }
  }

  const affectedAssets = investigation ? parseJsonArray(investigation.affected_assets) : []
  const attackSequence = investigation ? parseJsonArray(investigation.attack_sequence) : []

  const renderTabContent = () => {
    switch (activeTab) {
      case 'overview':
        return (
          <div className="space-y-6">
            <div className="bg-white shadow rounded-lg p-6">
              <h2 className="text-lg font-medium text-gray-900 mb-4">Incident Details</h2>
              <dl className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <dt className="text-sm font-medium text-gray-500">Title</dt>
                  <dd className="mt-1 text-lg font-semibold text-gray-900">{incident.title}</dd>
                </div>
                <div>
                  <dt className="text-sm font-medium text-gray-500">Severity</dt>
                  <dd className="mt-1">
                    <span className={`px-2 inline-flex text-xs leading-5 font-semibold rounded-full ${severityColors[incident.severity] || 'bg-gray-100 text-gray-800'}`}>
                      {incident.severity}
                    </span>
                  </dd>
                </div>
                <div>
                  <dt className="text-sm font-medium text-gray-500">Status</dt>
                  <dd className="mt-1 flex items-center">
                    {statusIcons[incident.status] || <FileText className="w-5 h-5 text-gray-400" />}
                    <span className="ml-2 capitalize text-gray-900">{incident.status}</span>
                  </dd>
                </div>
                <div>
                  <dt className="text-sm font-medium text-gray-500">Risk Score</dt>
                  <dd className="mt-1 text-lg font-semibold text-gray-900">{incident.risk_score}</dd>
                </div>
                <div>
                  <dt className="text-sm font-medium text-gray-500">Created</dt>
                  <dd className="mt-1 text-gray-900">{new Date(incident.created_at).toLocaleString()}</dd>
                </div>
                <div>
                  <dt className="text-sm font-medium text-gray-500">Updated</dt>
                  <dd className="mt-1 text-gray-900">{new Date(incident.updated_at).toLocaleString()}</dd>
                </div>
              </dl>
            </div>
            {incident.description && (
              <div className="bg-white shadow rounded-lg p-6">
                <h2 className="text-lg font-medium text-gray-900 mb-2">Description</h2>
                <p className="text-gray-700 whitespace-pre-wrap">{incident.description}</p>
              </div>
            )}
          </div>
        )
      case 'timeline':
        return (
          <div className="bg-white shadow rounded-lg overflow-hidden">
            <table className="min-w-full divide-y divide-gray-200">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">#</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Time</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Source</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Event Type</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">User</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">IP</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Host</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Action</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Severity</th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-200">
                {timeline.map((event) => (
                  <tr key={event.sequence_no} className="hover:bg-gray-50">
                    <td className="px-6 py-4 text-sm text-gray-900">{event.sequence_no}</td>
                    <td className="px-6 py-4 text-sm text-gray-500">{new Date(event.timestamp).toLocaleString()}</td>
                    <td className="px-6 py-4 text-sm text-gray-900">{event.source}</td>
                    <td className="px-6 py-4 text-sm text-gray-900">{event.event_type}</td>
                    <td className="px-6 py-4 text-sm text-gray-900">{event.username || '-'}</td>
                    <td className="px-6 py-4 text-sm text-gray-900">{event.source_ip || '-'}</td>
                    <td className="px-6 py-4 text-sm text-gray-900">{event.hostname || '-'}</td>
                    <td className="px-6 py-4 text-sm text-gray-900 max-w-xs truncate">{event.action || '-'}</td>
                    <td className="px-6 py-4 text-sm text-gray-900">{event.status || '-'}</td>
                    <td className="px-6 py-4 text-sm">
                      <span className={`px-2 inline-flex text-xs leading-5 font-semibold rounded-full ${severityColors[event.severity || 'low'] || 'bg-gray-100 text-gray-800'}`}>
                        {event.severity || 'low'}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )
      case 'alerts':
        return (
          <div className="space-y-4">
            {alerts.length === 0 ? (
              <div className="bg-white shadow rounded-lg p-8 text-center text-gray-500">No alerts for this incident</div>
            ) : (
              alerts.map((alert) => (
                <div key={alert.id} className="bg-white shadow rounded-lg p-6 border-l-4 border-blue-500">
                  <div className="flex justify-between">
                    <h3 className="font-medium text-gray-900">{alert.title}</h3>
                    <span className={`text-xs px-2 py-1 rounded ${severityColors[alert.severity] || 'bg-gray-100 text-gray-800'}`}>
                      {alert.severity}
                    </span>
                  </div>
                  <p className="text-sm text-gray-500 mt-2">{alert.description}</p>
                  <p className="text-xs text-gray-400 mt-2">{new Date(alert.created_at).toLocaleString()}</p>
                </div>
              ))
            )}
          </div>
        )
      case 'evidence':
        return (
          <div className="space-y-4">
            {evidence.length === 0 ? (
              <div className="bg-white shadow rounded-lg p-8 text-center text-gray-500">No evidence uploaded</div>
            ) : (
              evidence.map((ev) => (
                <div key={ev.id} className="bg-white shadow rounded-lg p-6 border">
                  <div className="flex justify-between items-start">
                    <div>
                      <h3 className="font-medium text-gray-900">{ev.filename}</h3>
                      <p className="text-sm text-gray-500 mt-1">{ev.file_type} • {ev.file_size} bytes</p>
                      <p className="text-xs text-gray-400 mt-1">SHA256: {ev.sha256}</p>
                    </div>
                    <span className="text-xs px-2 py-1 rounded bg-gray-100 text-gray-800">
                      {new Date(ev.uploaded_at).toLocaleString()}
                    </span>
                  </div>
                  {ev.description && <p className="text-sm text-gray-600 mt-2">{ev.description}</p>}
                </div>
              ))
            )}
          </div>
        )
      case 'ai':
        if (!investigation) {
          return (
            <div className="bg-white shadow rounded-lg p-8 text-center">
              <Brain className="w-12 h-12 mx-auto text-gray-400 mb-4" />
              <h3 className="text-lg font-medium text-gray-900 mb-2">No AI Investigation Yet</h3>
              <p className="text-gray-500 mb-4">Run the AI investigation to generate an attack story and recommendations.</p>
              <button
                onClick={async () => {
                  try {
                    await api.post(`/incidents/${incidentId}/investigate`)
                    window.location.reload()
                  } catch (e) {
                    alert('Failed to start investigation')
                  }
                }}
                className="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700"
              >
                Start AI Investigation
              </button>
            </div>
          )
        }
        return (
          <div className="space-y-6">
            <div className="bg-white shadow rounded-lg p-6">
              <h2 className="text-lg font-medium text-gray-900 mb-4 flex items-center">
                <Brain className="w-5 h-5 mr-2 text-blue-600" />
                AI Investigation Summary
              </h2>
              <dl className="space-y-4">
                <div>
                  <dt className="text-sm font-medium text-gray-500">Attack Type</dt>
                  <dd className="mt-1 text-gray-900">{investigation.attack_type || 'Unknown'}</dd>
                </div>
                <div>
                  <dt className="text-sm font-medium text-gray-500">Confidence</dt>
                  <dd className="mt-1 text-gray-900">{(investigation.confidence ?? 0) * 100}%</dd>
                </div>
                <div>
                  <dt className="text-sm font-medium text-gray-500">Root Cause</dt>
                  <dd className="mt-1 text-gray-900">{investigation.root_cause || 'Not determined'}</dd>
                </div>
                <div>
                  <dt className="text-sm font-medium text-gray-500">Affected Assets</dt>
                  <dd className="mt-1">
                    {affectedAssets.length ? (
                      <ul className="list-disc list-inside text-gray-900">
                        {affectedAssets.map((a: string, i: number) => <li key={i}>{a}</li>)}
                      </ul>
                    ) : (
                      <span className="text-gray-500">None</span>
                    )}
                  </dd>
                </div>
              </dl>
            </div>
            <div className="bg-white shadow rounded-lg p-6">
              <h2 className="text-lg font-medium text-gray-900 mb-4">Attack Sequence</h2>
              {attackSequence.length ? (
                <ol className="list-decimal list-inside space-y-2 text-gray-900">
                  {attackSequence.map((step: string, i: number) => <li key={i}>{step}</li>)}
                </ol>
              ) : (
                <p className="text-gray-500">No sequence available</p>
              )}
            </div>
          </div>
        )
      case 'mitre':
        return (
          <div className="bg-white shadow rounded-lg overflow-hidden">
            {mitre.length === 0 ? (
              <div className="p-8 text-center text-gray-500">No MITRE techniques mapped</div>
            ) : (
              <table className="min-w-full divide-y divide-gray-200">
                <thead className="bg-gray-50">
                  <tr>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Technique ID</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Name</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Tactic</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Confidence</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Evidence Ref</th>
                  </tr>
                </thead>
                <tbody className="bg-white divide-y divide-gray-200">
                  {mitre.map((t) => (
                    <tr key={t.technique_id} className="hover:bg-gray-50">
                      <td className="px-6 py-4 font-mono text-sm text-gray-900">{t.technique_id}</td>
                      <td className="px-6 py-4 text-sm text-gray-900">{t.name}</td>
                      <td className="px-6 py-4 text-sm text-gray-900">{t.tactic || 'Unknown'}</td>
                      <td className="px-6 py-4 text-sm text-gray-900">{(t.confidence * 100).toFixed(0)}%</td>
                      <td className="px-6 py-4 text-sm text-gray-500 font-mono">{t.evidence_ref || '-'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        )
      case 'recommendations':
        return (
          <div className="space-y-4">
            {recommendations.length === 0 ? (
              <div className="bg-white shadow rounded-lg p-8 text-center text-gray-500">No recommendations</div>
            ) : (
              recommendations.map((rec) => (
                <div key={rec.id} className="bg-white shadow rounded-lg p-6 border-l-4 border-green-500">
                  <div className="flex justify-between items-start">
                    <p className="text-gray-900">{rec.description}</p>
                    <span className={`text-xs px-2 py-1 rounded ${rec.priority === 'high' ? 'bg-red-100 text-red-800' : rec.priority === 'medium' ? 'bg-yellow-100 text-yellow-800' : 'bg-green-100 text-green-800'}`}>
                      {rec.priority || 'medium'}
                    </span>
                  </div>
                  <p className="text-xs text-gray-500 mt-2">
                    {rec.is_ai_generated ? '🤖 AI Generated' : '👤 Manual'}
                  </p>
                </div>
              ))
            )}
          </div>
        )
case 'report':
        const handleDownloadReport = async () => {
          try {
            const blob = (await api.get(`/incidents/${incidentId}/report`, {
              responseType: 'blob',
            })) as unknown as Blob;
            const url = window.URL.createObjectURL(blob);
            const link = document.createElement('a');
            link.href = url;
            link.setAttribute('download', `incident_${incidentId}_report.pdf`);
            document.body.appendChild(link);
            link.click();
            link.remove();
            window.URL.revokeObjectURL(url);
          } catch (err) {
            console.error('Failed to download report', err);
            alert('Failed to download report');
          }
        };
        return (
          <div className="bg-white shadow rounded-lg p-8 text-center">
            <Download className="w-12 h-12 mx-auto text-gray-400 mb-4" />
            <h3 className="text-lg font-medium text-gray-900 mb-2">Generate PDF Report</h3>
            <p className="text-gray-500 mb-4">Download a professional PDF report for this incident.</p>
            <button
              onClick={handleDownloadReport}
              className="px-6 py-3 bg-blue-600 text-white rounded hover:bg-blue-700 flex items-center justify-center mx-auto"
            >
              <Download className="w-5 h-5 mr-2" />
              Download Report
            </button>
          </div>
        )
      default:
        return null
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <Link to="/incidents" className="text-blue-600 hover:underline text-sm mb-2 inline-block">
            ← Back to Incidents
          </Link>
          <h1 className="text-2xl font-bold text-gray-900">{incident.title}</h1>
        </div>
        <div className="flex items-center space-x-4">
          <span className={`px-3 py-1 rounded-full text-sm font-medium ${severityColors[incident.severity] || 'bg-gray-100 text-gray-800'}`}>
            {incident.severity}
          </span>
          <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-gray-100 text-gray-800">
            {statusIcons[incident.status] || <FileText className="w-4 h-4" />}
            <span className="ml-1 capitalize">{incident.status}</span>
          </span>
          <span className="text-sm text-gray-500">Risk: {incident.risk_score}</span>
        </div>
      </div>

      <div className="border-b border-gray-200">
        <nav className="-mb-px flex space-x-8" aria-label="Tabs">
          {tabs.map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`py-4 px-1 border-b-2 font-medium text-sm flex items-center space-x-1 transition-colors ${
                activeTab === tab.id
                  ? 'border-blue-500 text-blue-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
              }`}
            >
              {tab.icon}
              <span>{tab.label}</span>
            </button>
          ))}
        </nav>
      </div>

      <div className="mt-6">
        {renderTabContent()}
      </div>
    </div>
  )
}