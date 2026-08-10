import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import api from '../services/api'
import { FileText, AlertTriangle, Clock, CheckCircle, ChevronRight, Upload, Loader2, Search, GitBranch } from 'lucide-react'

interface Incident {
  id: number
  title: string
  severity: string
  status: string
  risk_score: number
  created_at: string
}

export default function Incidents() {
  const [incidents, setIncidents] = useState<Incident[]>([])
  const [loading, setLoading] = useState(true)
  const [uploadModalOpen, setUploadModalOpen] = useState(false)
  const [uploadFile, setUploadFile] = useState<File | null>(null)
  const [uploadFormat, setUploadFormat] = useState<'auto'|'json'|'csv'|'linux_auth'|'windows_security'|'generic'>('auto')
  const [uploading, setUploading] = useState(false)
  const [uploadError, setUploadError] = useState<string | null>(null)
  const [uploadSuccess, setUploadSuccess] = useState<string | null>(null)

  const [detecting, setDetecting] = useState(false)
  const [correlating, setCorrelating] = useState(false)

  useEffect(() => {
    const fetchIncidents = async () => {
      try {
        const data = await api.get('/incidents?limit=100') as unknown as Incident[]
        setIncidents(data)
      } catch (e) {
        console.error('Failed to fetch incidents', e)
      } finally {
        setLoading(false)
      }
    }
    fetchIncidents()
  }, [])

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0] || null
    setUploadFile(file)
  }

  const handleUpload = async () => {
    if (!uploadFile) {
      setUploadError('Please select a file')
      return
    }
    setUploading(true)
    setUploadError(null)
    setUploadSuccess(null)
    const formData = new FormData()
    formData.append('file', uploadFile)
    if (uploadFormat !== 'auto') {
      formData.append('fmt', uploadFormat)
    }
    try {
      await api.post('/logs/upload', formData, {
        headers: { 'Content-Type': 'multipart/form-data' }
      })
      setUploadSuccess('Log file uploaded successfully')
      setUploadFile(null)
      // refresh incidents list
      const data = await api.get('/incidents?limit=100') as unknown as typeof incidents
      setIncidents(data)
    } catch (e: any) {
      setUploadError(e.response?.data?.detail || 'Upload failed')
    } finally {
      setUploading(false)
    }
  }

  const closeUploadModal = () => {
    setUploadModalOpen(false)
    setUploadFile(null)
    setUploadError(null)
    setUploadSuccess(null)
  }

  const handleRunDetection = async () => {
    setDetecting(true)
    try {
      await api.post('/alerts/run-detection?since_minutes=1000000')
      alert('Detection finished – alerts created')
      // refresh incidents list
      const data = await api.get('/incidents?limit=100') as unknown as typeof incidents
      setIncidents(data)
    } catch (e: any) {
      alert('Detection failed: ' + (e.response?.data?.detail || e.message))
    } finally {
      setDetecting(false)
    }
  }

  const handleCorrelate = async () => {
    setCorrelating(true)
    try {
      await api.post('/incidents/correlate?since_minutes=1000000')
      alert('Correlation finished – incidents created')
      const data = await api.get('/incidents?limit=100') as unknown as typeof incidents
      setIncidents(data)
    } catch (e: any) {
      alert('Correlation failed: ' + (e.response?.data?.detail || e.message))
    } finally {
      setCorrelating(false)
    }
  }

  const getSeverityColor = (sev: string) => {
    switch (sev) {
      case 'critical': return 'bg-red-100 text-red-800'
      case 'high': return 'bg-orange-100 text-orange-800'
      case 'medium': return 'bg-yellow-100 text-yellow-800'
      default: return 'bg-green-100 text-green-800'
    }
  }

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'open': return <AlertTriangle className="w-5 h-5 text-yellow-600" />
      case 'investigating': return <Clock className="w-5 h-5 text-blue-600" />
      case 'closed': return <CheckCircle className="w-5 h-5 text-green-600" />
      default: return <FileText className="w-5 h-5 text-gray-400" />
    }
  }

  if (loading) return <div className="flex items-center justify-center h-64">Loading...</div>

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center flex-wrap gap-2">
        <h1 className="text-2xl font-bold text-gray-900">Incidents</h1>
        <div className="flex items-center space-x-2 flex-wrap">
          <span className="text-sm text-gray-500">{incidents.length} incidents</span>
          <button
            onClick={() => setUploadModalOpen(true)}
            className="px-3 py-1.5 text-sm font-medium text-white bg-blue-600 rounded hover:bg-blue-700 flex items-center space-x-1"
          >
            <Upload className="w-4 h-4" />
            <span>Upload Logs</span>
          </button>
          <button
            onClick={handleRunDetection}
            disabled={detecting}
            className="px-3 py-1.5 text-sm font-medium text-white bg-green-600 rounded hover:bg-green-700 flex items-center space-x-1 disabled:opacity-50"
          >
            <Search className="w-4 h-4" />
            <span>{detecting ? <Loader2 className="w-4 h-4 animate-spin" /> : 'Run Detection'}</span>
          </button>
          <button
            onClick={handleCorrelate}
            disabled={correlating}
            className="px-3 py-1.5 text-sm font-medium text-white bg-purple-600 rounded hover:bg-purple-700 flex items-center space-x-1 disabled:opacity-50"
          >
            <GitBranch className="w-4 h-4" />
            <span>{correlating ? <Loader2 className="w-4 h-4 animate-spin" /> : 'Correlate Alerts'}</span>
          </button>
        </div>
      </div>

      {/* Upload Modal */}
      {uploadModalOpen && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white rounded-lg p-6 w-full max-w-md mx-4">
            <h2 className="text-lg font-semibold mb-4">Upload Log File</h2>
            <input
              type="file"
              accept=".json,.csv,.log,.txt"
              onChange={handleFileChange}
              className="mb-3 w-full"
            />
            <select
              value={uploadFormat}
              onChange={(e) => setUploadFormat(e.target.value as any)}
              className="mb-3 w-full p-2 border rounded"
            >
              <option value="auto">Auto detect</option>
              <option value="json">JSON</option>
              <option value="csv">CSV</option>
              <option value="linux_auth">Linux auth.log</option>
              <option value="windows_security">Windows Security</option>
              <option value="generic">Generic</option>
            </select>
            {uploadError && <p className="text-red-600 mb-2">{uploadError}</p>}
            {uploadSuccess && <p className="text-green-600 mb-2">{uploadSuccess}</p>}
            <div className="flex justify-end space-x-2">
              <button onClick={closeUploadModal} className="px-4 py-2 text-gray-700 hover:bg-gray-100 rounded">Cancel</button>
              <button
                onClick={handleUpload}
                disabled={uploading}
                className="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700 disabled:opacity-50"
              >
                {uploading ? <Loader2 className="w-4 h-4 animate-spin" /> : 'Upload'}
              </button>
            </div>
          </div>
        </div>
      )}

      <div className="bg-white shadow rounded-lg overflow-hidden">
        <table className="min-w-full divide-y divide-gray-200">
          <thead className="bg-gray-50">
            <tr>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Title</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Severity</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Risk Score</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Created</th>
              <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
            </tr>
          </thead>
          <tbody className="bg-white divide-y divide-gray-200">
            {incidents.length === 0 ? (
              <tr>
                <td colSpan={6} className="px-6 py-12 text-center text-gray-500">No incidents found</td>
              </tr>
            ) : (
              incidents.map((incident) => (
                <tr key={incident.id} className="hover:bg-gray-50">
                  <td className="px-6 py-4">
                    <Link to={`/incidents/${incident.id}`} className="font-medium text-gray-900 hover:text-blue-600">
                      {incident.title}
                    </Link>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <span className={`px-2 inline-flex text-xs leading-5 font-semibold rounded-full ${getSeverityColor(incident.severity)}`}>
                      {incident.severity}
                    </span>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-gray-100 text-gray-800">
                      {getStatusIcon(incident.status)}
                      <span className="ml-1 capitalize">{incident.status}</span>
                    </span>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{incident.risk_score}</td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                    {new Date(incident.created_at).toLocaleString()}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                    <Link to={`/incidents/${incident.id}`} className="text-blue-600 hover:text-blue-900 flex items-center justify-end">
                      <ChevronRight className="w-4 h-4" />
                    </Link>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}