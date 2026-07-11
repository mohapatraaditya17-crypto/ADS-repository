import type { Metadata } from 'next'
import './globals.css'

export const metadata: Metadata = {
  title: 'Falcon AI Copilot - CrowdStrike SOC Assistant',
  description: 'Enterprise AI Copilot operating in strictly read-only mode for CrowdStrike Falcon SOC operations.',
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en">
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="anonymous" />
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet" />
      </head>
      <body className="bg-background text-textMain h-screen overflow-hidden">
        {children}
      </body>
    </html>
  )
}
