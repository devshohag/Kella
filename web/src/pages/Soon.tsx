// Placeholder for screens planned in later phases (SPEC §17). Replace page by page.
export function Soon({ title, phase }: { title: string; phase: string }) {
  return (
    <div className="page">
      <h1>{title}</h1>
      <section className="panel"><div className="empty">This screen is planned for {phase}. See docs/design for the target layout.</div></section>
    </div>
  )
}
