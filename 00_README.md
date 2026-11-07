# SAML, OAuth 2.0 and OIDC — Learning Series

**Audience:** cloud, identity, platform and security engineers.  
**Goal:** understand the terminology, follow the trust exchanges, validate security boundaries, then implement the patterns in AWS and Microsoft Entra ID.

## Suggested reading order

| Order | Document | Read it to answer |
|---|---|---|
| 1 | [01_Terminology_and_Mental_Models.md](01_Terminology_and_Mental_Models.md) | Who is the client, IdP, subject, issuer, audience and bearer? |
| 2 | [02_SAML_2_0_Fundamentals.md](02_SAML_2_0_Fundamentals.md) | How does enterprise browser SSO work? |
| 3 | [03_OAuth_2_0_and_OIDC.md](03_OAuth_2_0_and_OIDC.md) | Why two protocols, which tokens and endpoints, and what is PKCE? |
| 4 | [04_JWT_JWKS_and_Token_Validation.md](04_JWT_JWKS_and_Token_Validation.md) | How do cryptographic signatures and claim checks establish trust? |
| 5 | [05_AWS_Entra_and_GitHub_Flows.md](05_AWS_Entra_and_GitHub_Flows.md) | How do ALB and AWS STS use federation differently? |
| 6 | [06_Architecture_Decisions_and_Advanced_Concepts.md](06_Architecture_Decisions_and_Advanced_Concepts.md) | Which pattern should I choose and what can fail? |

## One-minute overview

- **SAML 2.0** federates authentication using signed XML statements, typically between an IdP and a web Service Provider (SP).
- **OAuth 2.0** authorizes clients to access protected resources, commonly through access tokens.
- **OIDC** builds on OAuth to give a client a standardized authentication result, the **ID token**.
- **Workload federation** uses a platform-issued assertion (often an OIDC JWT) to obtain short-lived cloud credentials, without interactive user login.
- **AWS STS** is a credential exchange service; it is not itself an OIDC identity provider.

## Four questions before any design

1. **Who or what is the subject?** Human, service, or CI job?
2. **Who is the consumer?** A web application, API, or AWS STS?
3. **What proof crosses the boundary?** SAML response, authorization code, ID token, access token, or workload assertion?
4. **What establishes trust?** Issuer, signature/key, audience, lifetime, request correlation, and policies?

## Scope and editorial notes

These are revised and consolidated versions of the uploaded *SAML_OIDC_Still_Confusion.md* and *F1_OIDC_vs_SAML_Roles_Clients_Flows.md*. The originals contained useful flow and security detail but mixed human login with workload-token exchange, and sometimes described common patterns as universal rules. The new series distinguishes **generic protocol behavior** from **AWS-specific implementation**. All examples are illustrative, not captured credentials.

**Noteworthy corrections:** ALB actively calls the UserInfo endpoint and forwards ALB-signed claims (not the original ID token); GitHub-to-AWS uses `AssumeRoleWithWebIdentity`, not browser Authorization Code Flow; access tokens can be opaque *or* JWTs; `azp` is not universally required; an `aud` claim may contain multiple permitted audiences; SAML metadata can be refreshed automatically; and nonce/PKCE checks depend on the selected flow and provider behavior.

## Primary references

- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html)
- [RFC 6749 — OAuth 2.0](https://www.rfc-editor.org/rfc/rfc6749)
- [RFC 9700 — OAuth 2.0 Security Best Current Practice](https://www.rfc-editor.org/rfc/rfc9700)
- [OASIS SAML 2.0 specifications](https://docs.oasis-open.org/security/saml/v2.0/)
- [AWS ALB authenticate users](https://docs.aws.amazon.com/elasticloadbalancing/latest/application/listener-authenticate-users.html)
- [AWS IAM OIDC role trust](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-idp_oidc.html)
- [GitHub OIDC in AWS](https://docs.github.com/en/actions/how-tos/secure-your-work/security-harden-deployments/oidc-in-aws)
