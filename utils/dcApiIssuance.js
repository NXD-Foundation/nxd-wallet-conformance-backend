export function offeredCredentialConfigurationIds(session) {
  const offered = session?.dcApiState?.credentialConfigurationIds;
  if (Array.isArray(offered)) return offered;
  if (Array.isArray(session?.requestedCredentialConfigurationIds)) return session.requestedCredentialConfigurationIds;
  return session?.credentialType ? [session.credentialType] : [];
}
