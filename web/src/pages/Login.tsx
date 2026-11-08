import { useMutation, useQuery } from '@tanstack/react-query'
import { useState } from 'react'
import { Navigate, useNavigate } from 'react-router-dom'
import { api, type TotpSetup } from '../api'
import styles from './Login.module.css'

export function Login() {
  const navigate = useNavigate()
  const session = useQuery({ queryKey: ['me'], queryFn: api.me, retry: false, staleTime: 30_000 })
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [code, setCode] = useState('')
  const [setup, setSetup] = useState<TotpSetup | null>(null)

  const signIn = useMutation({
    mutationFn: () => api.login(email, password, code),
    onSuccess: async (result) => {
      if (result.totpSetupRequired && result.setupToken) {
        setSetup(await api.totpSetup(result.setupToken))
        return
      }
      navigate('/', { replace: true })
    },
  })

  const enable = useMutation({
    mutationFn: () => api.totpEnable(setupToken, code),
    onSuccess: () => navigate('/', { replace: true }),
  })

  const setupToken = signIn.data?.setupToken ?? ''

  if (session.data) return <Navigate to="/" replace />

  return (
    <div className={styles.page}>
      <form
        className={styles.card}
        onSubmit={(e) => {
          e.preventDefault()
          if (setup) enable.mutate()
          else signIn.mutate()
        }}
      >
        <div className={styles.brand}>
          <svg width="30" height="30" viewBox="0 0 24 24" aria-hidden="true">
            <path d="M12 1.8l8.6 3.6v6.2c0 5.4-3.6 9.9-8.6 11.2-5-1.3-8.6-5.8-8.6-11.2V5.4z" fill="var(--info)" />
            <path d="M12 6.5v10.5M7.5 10.2h9" stroke="#fff" strokeWidth="2" />
          </svg>
          <span>Kella</span>
        </div>

        {setup ? (
          <>
            <h1 className={styles.title}>Set up two-factor authentication</h1>
            <p className="sub">
              Owner and admin accounts need an authenticator code. Add this secret to your authenticator app,
              then enter the six-digit code it shows.
            </p>
            <label className={styles.field}>
              <span>Secret</span>
              <code className={`mono ${styles.secret}`}>{setup.secret}</code>
            </label>
            <label className={styles.field}>
              <span>Authenticator URI</span>
              <code className={`mono ${styles.secret}`}>{setup.otpauthUri}</code>
            </label>
            <label className={styles.field}>
              <span>Six-digit code</span>
              <input
                value={code}
                onChange={(e) => setCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                inputMode="numeric"
                autoComplete="one-time-code"
                autoFocus
                required
                pattern="\d{6}"
              />
            </label>
            {enable.isError && <p className="error">{enable.error.message}</p>}
            <button className={`btn primary ${styles.submit}`} type="submit" disabled={enable.isPending}>
              {enable.isPending ? 'Enabling…' : 'Enable two-factor authentication'}
            </button>
            <button
              className={styles.link}
              type="button"
              onClick={() => { setSetup(null); signIn.reset(); setCode('') }}
            >
              Start over
            </button>
          </>
        ) : (
          <>
            <h1 className={styles.title}>Sign in</h1>
            <p className="sub">Use your organization email and password.</p>
            <label className={styles.field}>
              <span>Email</span>
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                autoComplete="email"
                autoFocus
                required
              />
            </label>
            <label className={styles.field}>
              <span>Password</span>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoComplete="current-password"
                required
              />
            </label>
            <label className={styles.field}>
              <span>Two-factor code <em className={styles.optional}>if enabled</em></span>
              <input
                value={code}
                onChange={(e) => setCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                inputMode="numeric"
                autoComplete="one-time-code"
                pattern="\d{6}"
              />
            </label>
            {signIn.isError && <p className="error">{signIn.error.message}</p>}
            <button className={`btn primary ${styles.submit}`} type="submit" disabled={signIn.isPending}>
              {signIn.isPending ? 'Signing in…' : 'Sign in'}
            </button>
          </>
        )}
      </form>
    </div>
  )
}
