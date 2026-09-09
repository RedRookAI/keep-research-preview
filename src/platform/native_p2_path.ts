/** Shared P2 canonical relative regular-file path grammar. Pure and non-authorizing. */
export const NATIVE_P2_RELATIVE_PATH = /^(?!\/)(?!.*(?:^|\/)\.\.?(?:\/|$))(?!.*\/\/)[A-Za-z0-9._+-]+(?:\/[A-Za-z0-9._+-]+)*$/;

export function isCanonicalNativeP2RelativePath(path: string): boolean {
  return NATIVE_P2_RELATIVE_PATH.test(path);
}
