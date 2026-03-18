import { Outlet, HeadContent, Scripts, createRootRoute } from '@tanstack/react-router'
import { LocaleProvider, useLocale } from '../i18n'
import '../styles.css'

export const Route = createRootRoute({
  head: () => ({
    meta: [
      { charSet: 'utf-8' },
      { name: 'viewport', content: 'width=device-width, initial-scale=1, viewport-fit=cover' },
      { title: 'zk-eidas — Zero-Knowledge Selective Disclosure for eIDAS 2.0' },
      { name: 'description', content: 'Prove claims about your identity without revealing personal data. Open-source ZK circuit library for eIDAS 2.0 credentials (SD-JWT VC & mdoc) with ECDSA P-256 verified in-circuit.' },
      { name: 'theme-color', content: '#0f172a' },
      { property: 'og:title', content: 'zk-eidas — Zero-Knowledge Selective Disclosure for eIDAS 2.0' },
      { property: 'og:description', content: 'Prove claims about your identity without revealing personal data. Open-source ZK circuit library for eIDAS 2.0 credentials with ECDSA P-256 verified in-circuit.' },
      { property: 'og:image', content: 'https://zk-eidas.com/og-image.png' },
      { property: 'og:url', content: 'https://zk-eidas.com' },
      { property: 'og:type', content: 'website' },
      { name: 'twitter:card', content: 'summary_large_image' },
      { name: 'twitter:title', content: 'zk-eidas — ZK Selective Disclosure for eIDAS 2.0' },
      { name: 'twitter:description', content: 'Prove identity claims without revealing personal data. ECDSA P-256 verified in-circuit. Open source.' },
      { name: 'twitter:image', content: 'https://zk-eidas.com/og-image.png' },
    ],
  }),
  component: RootComponent,
})

function RootComponent() {
  return (
    <LocaleProvider>
      <RootLayout />
    </LocaleProvider>
  )
}

function RootLayout() {
  const { locale } = useLocale()
  return (
    <html lang={locale}>
      <head>
        <HeadContent />
        <link rel="icon" type="image/svg+xml" href="/favicon.svg" />
        <link rel="manifest" href="/manifest.json" />
        <link rel="apple-touch-icon" href="/icon-192.png" />
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="" />
        <link href="https://fonts.googleapis.com/css2?family=Cormorant+Garamond:ital,wght@0,400;0,600;0,700;1,400&family=Outfit:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet" />
      </head>
      <body className="bg-slate-900">
        <Outlet />
        <Scripts />
        <script dangerouslySetInnerHTML={{ __html: `
          if ('serviceWorker' in navigator) {
            navigator.serviceWorker.register('/sw.js')
          }
        ` }} />
      </body>
    </html>
  )
}
