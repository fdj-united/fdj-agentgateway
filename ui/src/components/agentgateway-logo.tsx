/* eslint-disable @next/next/no-img-element */
// Plain <img> on purpose: this asset lives in /public and the production build
// is a static export served by the Rust proxy at /ui — no Next image optimizer.
export function AgentgatewayLogo({ className }: { className?: string }) {
  return <img src="/ui/favicon.png" alt="Logo" className={className} />;
}
