pub use super::opaque_token::OpaqueToken as VerificationToken;

use super::opaque_token::OpaqueTokenService;

/// Emails a one-time token and stores only its hash.
///
/// It is a marker trait over [`OpaqueTokenService`], so the same generator can
/// also back MFA challenges without pretending they verify an email.
pub trait VerificationTokenService: OpaqueTokenService {}

impl<T: OpaqueTokenService + ?Sized> VerificationTokenService for T {}
