import { Outlet, NavLink, useNavigate } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'
import { LogOut, LayoutDashboard, FileText } from 'lucide-react'

export default function Layout() {
  const { user, logout } = useAuth()
  const navigate = useNavigate()

  const handleLogout = () => {
    logout()
    navigate('/login')
  }

  return (
    <div className="min-h-screen bg-gray-50">
      <nav className="bg-white shadow-sm border-b">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between h-16">
            <div className="flex items-center">
              <h1 className="text-xl font-bold text-gray-900">SentinelX</h1>
            </div>
            <div className="flex items-center space-x-4">
              <NavLink
                to="/"
                className={({ isActive }) =>
                  `px-3 py-2 rounded-md text-sm font-medium ${isActive ? 'bg-blue-50 text-blue-700' : 'text-gray-500 hover:text-gray-700'}`
                }
              >
                <LayoutDashboard className="inline-block w-4 h-4 mr-1" />
                Dashboard
              </NavLink>
              <NavLink
                to="/incidents"
                className={({ isActive }) =>
                  `px-3 py-2 rounded-md text-sm font-medium ${isActive ? 'bg-blue-50 text-blue-700' : 'text-gray-500 hover:text-gray-700'}`
                }
              >
                <FileText className="inline-block w-4 h-4 mr-1" />
                Incidents
              </NavLink>
              <div className="flex items-center space-x-2">
                <span className="text-sm text-gray-700">{user?.email}</span>
                <span className={`px-2 py-1 text-xs rounded-full ${
                  user?.role === 'admin' ? 'bg-purple-100 text-purple-800' :
                  user?.role === 'analyst' ? 'bg-blue-100 text-blue-800' :
                  'bg-green-100 text-green-800'
                }`}>{user?.role}</span>
                <button onClick={handleLogout} className="text-gray-500 hover:text-gray-700">
                  <LogOut className="w-5 h-5" />
                </button>
              </div>
            </div>
          </div>
        </div>
      </nav>
      <main className="max-w-7xl mx-auto py-6 px-4 sm:px-6 lg:px-8">
        <Outlet />
      </main>
    </div>
  )
}