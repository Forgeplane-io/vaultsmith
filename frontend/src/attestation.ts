import type { components } from './generated/api'
import * as z from 'zod/mini'

export type SignedAttestation = components['schemas']['RotationAttestation']

export const signedAttestationSchema = z.object({
  protected: z.string(),
  payload: z.string(),
  signature: z.string(),
}) satisfies z.ZodMiniType<SignedAttestation>

export function parseSignedAttestationText(value: string): SignedAttestation | null {
  try {
    const result = signedAttestationSchema.safeParse(JSON.parse(value))
    return result.success ? result.data : null
  } catch {
    return null
  }
}
