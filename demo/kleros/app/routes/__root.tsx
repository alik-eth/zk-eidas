import { Outlet, HeadContent, Scripts, createRootRoute, Link } from '@tanstack/react-router'
import { WagmiProvider } from 'wagmi'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { config } from '../lib/wagmi'
import { WalletConnect } from '../components/WalletConnect'
import '../styles.css'

const queryClient = new QueryClient()

export const Route = createRootRoute({
  head: () => ({
    meta: [
      { charSet: 'utf-8' },
      { name: 'viewport', content: 'width=device-width, initial-scale=1' },
      { title: 'zk-eidas x Kleros  —  Identity Escrow' },
      { name: 'description', content: 'Decentralized identity escrow with ZK proofs, Kleros arbitration, and Lit Protocol encryption.' },
    ],
  }),
  component: RootComponent,
})

function RootComponent() {
  return (
    <html lang="en">
      <head>
        <HeadContent />
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="" />
        <link
          href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap"
          rel="stylesheet"
        />
      </head>
      <body className="bg-slate-900 text-white" style={{ fontFamily: "'Outfit', sans-serif" }}>
        <WagmiProvider config={config}>
          <QueryClientProvider client={queryClient}>
            {/* Navigation */}
            <header className="border-b border-slate-800 bg-slate-950/80 backdrop-blur-md sticky top-0 z-50">
              <div className="max-w-5xl mx-auto px-4 sm:px-8 py-4 flex items-center justify-between">
                <Link to="/" className="flex items-center gap-3">
                  <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-purple-600 to-blue-600 flex items-center justify-center">
                    <span className="text-[10px] font-bold text-white tracking-tighter">zK</span>
                  </div>
                  <div>
                    <h1 className="text-sm font-semibold tracking-tight leading-none">
                      <span className="text-blue-400">zk-eidas</span>
                      <span className="text-slate-600 mx-1">x</span>
                      <span className="text-purple-400">Kleros</span>
                    </h1>
                    <span className="text-[10px] text-slate-600 tracking-wide">Identity Escrow</span>
                  </div>
                </Link>

                <nav className="flex items-center gap-2 sm:gap-4">
                  <Link
                    to="/escrow"
                    className="text-xs font-medium text-slate-400 hover:text-white transition-colors px-3 py-1.5 rounded-lg hover:bg-slate-800"
                  >
                    Escrow
                  </Link>
                  <Link
                    to="/dispute"
                    className="text-xs font-medium text-slate-400 hover:text-white transition-colors px-3 py-1.5 rounded-lg hover:bg-slate-800"
                  >
                    Dispute
                  </Link>
                  <Link
                    to="/resolve"
                    className="text-xs font-medium text-slate-400 hover:text-white transition-colors px-3 py-1.5 rounded-lg hover:bg-slate-800"
                  >
                    Resolve
                  </Link>
                  <WalletConnect />
                </nav>
              </div>
            </header>

            <Outlet />
          </QueryClientProvider>
        </WagmiProvider>
        <Scripts />
      </body>
    </html>
  )
}
