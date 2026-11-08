import { NavLink, Outlet } from 'react-router-dom'
import styles from './Layout.module.css'

const nav = [
  { to: '/', label: 'Overview', end: true },
  { to: '/incidents', label: 'Incidents' },
  { to: '/servers', label: 'Servers' },
  { to: '/tenants', label: 'Tenants', todo: true },
]
const guards = [
  { to: '/mail', label: 'Mail Guard', todo: true },
  { to: '/web', label: 'Web Guard', todo: true },
  { to: '/voice', label: 'Voice Guard', todo: true },
]
const settings = [{ to: '/settings/alerts', label: 'Alerts', todo: true }]

function Item({ to, label, end, todo }: { to: string; label: string; end?: boolean; todo?: boolean }) {
  return (
    <NavLink to={to} end={end} className={({ isActive }) => `${styles.item} ${isActive ? styles.active : ''}`}>
      {label}
      {todo && <span className={styles.soon}>Soon</span>}
    </NavLink>
  )
}

export function Layout() {
  return (
    <div className={styles.shell}>
      <aside className={styles.rail}>
        <div className={styles.brand}>
          <svg width="26" height="26" viewBox="0 0 24 24" aria-hidden="true">
            <path d="M12 1.8l8.6 3.6v6.2c0 5.4-3.6 9.9-8.6 11.2-5-1.3-8.6-5.8-8.6-11.2V5.4z" fill="var(--info)" />
            <path d="M12 6.5v10.5M7.5 10.2h9" stroke="#fff" strokeWidth="2" />
          </svg>
          Kella
        </div>
        <nav aria-label="Main">
          {nav.map((n) => <Item key={n.to} {...n} />)}
          <div className={styles.group}>Guards</div>
          {guards.map((n) => <Item key={n.to} {...n} />)}
          <hr className={styles.rule} />
          {settings.map((n) => <Item key={n.to} {...n} />)}
        </nav>
      </aside>
      <main className={styles.main}>
        <Outlet />
      </main>
    </div>
  )
}
