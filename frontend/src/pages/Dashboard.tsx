import { useEffect, useState } from 'react'
import api from '../services/api'
import {
  PieChart, Pie, Cell, ResponsiveContainer, Tooltip, Legend
} from 'recharts'
import { AlertTriangle, FileText, Clock, CheckCircle } from 'lucide-react'

interface StatCardProps {
  title: string
  value: number | string
  icon: React.ReactNode
  color: string
  subtitle?: string
}

function StatCard({ title, value, icon, color, subtitle }: StatCardProps) {
  return (
    <div className="bg-white overflow-hidden shadow rounded-lg">
      <div className="p-5">
        <div className="flex items-center">
          <div className={`flex-shrink-0 p-2 rounded-md ${color} text-white`}>
            {icon}
          </div>
          <div className="ml-5 w-0 flex-1">
            <dl>
              <dt className="text-sm font-medium text-gray-500 truncate">{title}</dt>
              <dd className="text-2xl font-semibold text-gray-900">{value}</dd>
              {subtitle && <dd className="text-sm text-gray-500">{subtitle}</dd>}
            </dl>
          </div>
        </div>
      </div>
    </div>
  )
}

export default function Dashboard() {
  const [stats, setStats] = useState({
    totalIncidents: 0,
    criticalIncidents: 0,
    activeIncidents: 0,
    resolvedIncidents: 0,
  })
  const [severityData, setSeverityData] = useState<{name: string, value: number}[]>([])
  const [recentAlerts, setRecentAlerts] = useState<any[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const fetchData = async () => {
      try {
        const incidents = (await api.get('/incidents?limit=100')) as any[]
        const alerts = (await api.get('/alerts?limit=10')) as any[]

        setStats({
          totalIncidents: incidents.length,
          criticalIncidents: incidents.filter((i: any) => i.severity === 'critical').length,
          activeIncidents: incidents.filter((i: any) => i.status === 'open' || i.status === 'investigating').length,
          resolvedIncidents: incidents.filter((i: any) => i.status === 'closed').length,
        })

        // severity distribution
        const sevMap: Record<string, number> = {}
        incidents.forEach((i: any) => {
          sevMap[i.severity] = (sevMap[i.severity] || 0) + 1
        })
        setSeverityData(Object.entries(sevMap).map(([name, value]) => ({ name, value })))

        setRecentAlerts(alerts)
      } catch (e) {
        console.error('Failed to fetch dashboard data', e)
      } finally {
        setLoading(false)
      }
    }
    fetchData()
  }, [])

  if (loading) {
    return <div className="flex items-center justify-center h-64">Loading...</div>
  }

  const COLORS = ['#ef4444', '#f97316', '#eab308', '#22c55e']

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold text-gray-900">Dashboard</h1>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="Total Incidents"
          value={stats.totalIncidents}
          icon={<FileText className="w-6 h-6" />}
          color="bg-blue-500"
        />
        <StatCard
          title="Critical"
          value={stats.criticalIncidents}
          icon={<AlertTriangle className="w-6 h-6" />}
          color="bg-red-500"
        />
        <StatCard
          title="Active"
          value={stats.activeIncidents}
          icon={<Clock className="w-6 h-6" />}
          color="bg-yellow-500"
        />
        <StatCard
          title="Resolved"
          value={stats.resolvedIncidents}
          icon={<CheckCircle className="w-6 h-6" />}
          color="bg-green-500"
        />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-white shadow rounded-lg p-6">
          <h2 className="text-lg font-medium text-gray-900 mb-4">Severity Distribution</h2>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={severityData}
                  cx="50%"
                  cy="50%"
                  innerRadius={60}
                  outerRadius={80}
                  fill="#8884d8"
                  paddingAngle={2}
                  dataKey="value"
                  nameKey="name"
                  label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                >
                  {severityData.map((_entry, index) => (
                    <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip />
                <Legend />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="bg-white shadow rounded-lg p-6">
          <h2 className="text-lg font-medium text-gray-900 mb-4">Recent Alerts</h2>
          <div className="space-y-3">
            {recentAlerts.length === 0 ? (
              <p className="text-gray-500 text-center py-4">No recent alerts</p>
            ) : (
              recentAlerts.map((alert: any) => (
                <div key={alert.id} className="border-l-4 border-blue-500 pl-4 py-2 bg-gray-50 rounded-r">
                  <div className="flex justify-between">
                    <span className="font-medium text-gray-900">{alert.title}</span>
                    <span className={`text-xs px-2 py-1 rounded ${
                      alert.severity === 'critical' ? 'bg-red-100 text-red-800' :
                      alert.severity === 'high' ? 'bg-orange-100 text-orange-800' :
                      alert.severity === 'medium' ? 'bg-yellow-100 text-yellow-800' :
                      'bg-green-100 text-green-800'
                    }`}>{alert.severity}</span>
                  </div>
                  <p className="text-sm text-gray-500 mt-1">{alert.description}</p>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  )
}