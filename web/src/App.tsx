import { Route, Routes } from 'react-router-dom'
import { Layout } from './components/Layout'
import { IncidentDetail, Incidents } from './pages/Incidents'
import { Overview } from './pages/Overview'
import { Servers } from './pages/Servers'
import { Soon } from './pages/Soon'

export default function App() {
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route index element={<Overview />} />
        <Route path="incidents" element={<Incidents />} />
        <Route path="incidents/:id" element={<IncidentDetail />} />
        <Route path="servers" element={<Servers />} />
        <Route path="tenants" element={<Soon title="Tenants" phase="Phase 2" />} />
        <Route path="mail" element={<Soon title="Mail Guard" phase="Phase 2" />} />
        <Route path="web" element={<Soon title="Web Guard" phase="Phase 3" />} />
        <Route path="voice" element={<Soon title="Voice Guard" phase="Phase 5" />} />
        <Route path="settings/alerts" element={<Soon title="Alerts" phase="Phase 4" />} />
        <Route path="*" element={<Soon title="Page not found" phase="no phase — check the address" />} />
      </Route>
    </Routes>
  )
}
