import { useQuery } from '@tanstack/react-query'
import type { ReactNode } from 'react'
import { Navigate } from 'react-router-dom'
import { api } from '../api'

/** Sends unauthenticated visitors to the login page (SPEC §5, §16). */
export function RequireAuth({ children }: { children: ReactNode }) {
  const session = useQuery({ queryKey: ['me'], queryFn: api.me, retry: false, staleTime: 30_000 })
  if (session.isLoading) return null
  if (session.isError || !session.data) return <Navigate to="/login" replace />
  return <>{children}</>
}
