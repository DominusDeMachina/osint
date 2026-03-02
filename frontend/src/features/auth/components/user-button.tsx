import { UserButton as ClerkUserButton } from '@clerk/clerk-react'

export function UserButton() {
  return (
    <ClerkUserButton
      afterSignOutUrl="/sign-in"
      appearance={{
        elements: {
          avatarBox: 'h-8 w-8',
        },
      }}
    />
  )
}
