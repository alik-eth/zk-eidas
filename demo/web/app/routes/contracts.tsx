import { createFileRoute, redirect } from '@tanstack/react-router'

export const Route = createFileRoute('/contracts')({
  beforeLoad: () => {
    throw redirect({ to: '/demo' })
  },
})
