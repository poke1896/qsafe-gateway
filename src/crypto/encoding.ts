export const b64u = {
  encode: (bytes: Uint8Array): string => Buffer.from(bytes).toString('base64url'),
  decode: (value: string): Uint8Array => {
    if (!/^[A-Za-z0-9_-]*$/.test(value)) throw new Error('invalid base64url')
    return new Uint8Array(Buffer.from(value, 'base64url'))
  },
}
