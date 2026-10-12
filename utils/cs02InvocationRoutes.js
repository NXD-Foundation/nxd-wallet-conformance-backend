import { resolveCs02InvocationSchemeInput } from "./cs02VerifierRequest.js";

// Run before generation so invalid input cannot create a session or sign a JAR.
export function validateCs02InvocationScheme(req, res, next) {
  try {
    req.cs02InvocationScheme = resolveCs02InvocationSchemeInput(
      req.query?.invocation_scheme,
      req.body?.invocation_scheme,
    );
    return next();
  } catch (error) {
    return res.status(400).json({ error: "invalid_request", error_description: error.message });
  }
}

export function rejectDcApiInvocationScheme(req, res, next) {
  if (req.query?.invocation_scheme !== undefined || req.body?.invocation_scheme !== undefined) {
    return res.status(400).json({
      error: "invalid_request",
      error_description: "invocation_scheme does not apply to the Digital Credentials API",
    });
  }
  return next();
}
