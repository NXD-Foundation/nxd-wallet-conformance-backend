/**
 * VP response correlation helpers (OpenID4VP direct_post.jwt state).
 * Centralizes rules so verifierRoutes and tests stay aligned.
 */

/**
 * @param {unknown} value
 * @returns {string|null}
 */
export function normalizeVpStateInput(value) {
  if (value == null) return null;
  const s = String(value).trim();
  return s === "" ? null : s;
}

/**
 * Validate state for direct_post.jwt: form body vs outer response JWT, then vs session.
 *
 * @param {{ formStateRaw?: unknown, outerJwtStateRaw?: unknown, sessionStateRaw?: unknown }} p
 * @returns {{ ok: true, submittedState: string | null } | { ok: false, error: string, sessionError: string, sessionErrorDescription: string }}
 */
export function evaluateDirectPostJwtStateCorrelation(p) {
  const formState = normalizeVpStateInput(p.formStateRaw);
  const jwtState = normalizeVpStateInput(p.outerJwtStateRaw);
  const sessionState = normalizeVpStateInput(p.sessionStateRaw);

  if (formState && jwtState && formState !== jwtState) {
    const err = `state mismatch between form body and response JWT. Form: '${formState}', JWT: '${jwtState}'`;
    return {
      ok: false,
      error: err,
      sessionError: "failed_correlation",
      sessionErrorDescription: `state mismatch between form body and response JWT. Form: '${formState}', JWT: '${jwtState}'.`,
    };
  }

  const submitted = formState ?? jwtState;

  if (sessionState) {
    if (!submitted) {
      const err = `state missing in direct_post.jwt. Expected: '${sessionState}' in response JWT payload or form body`;
      return {
        ok: false,
        error: err,
        sessionError: "failed_correlation",
        sessionErrorDescription: err,
      };
    }
    if (submitted !== sessionState) {
      const err = `state mismatch in direct_post.jwt. Received: '${submitted}', expected: '${sessionState}'`;
      return {
        ok: false,
        error: err,
        sessionError: "failed_correlation",
        sessionErrorDescription: err,
      };
    }
  }

  return { ok: true, submittedState: submitted };
}
