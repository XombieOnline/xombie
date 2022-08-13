use crate::AuthorizationData;

/// (*AD-MANDATORY-FOR-KDC*) Type of *AuthorizationData*.
/// Defined in RFC4120, section 5.2.6.4.
/// ```asn1
/// AD-MANDATORY-FOR-KDC    ::= AuthorizationData
/// ```
pub type AdMandatoryForKdc = AuthorizationData;
