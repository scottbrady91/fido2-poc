namespace ScottBrady.Fido2;

public static class FidoConstants
{
    /// <summary>
    /// Known transports the client (WebAuthn API) can use to communicate with an authenticator.
    /// Values from <a href="https://www.w3.org/TR/webauthn-2/#enum-transport">Authenticator Transport Enumeration</a>.
    /// </summary>
    public static class AuthenticatorTransport
    {
        /// <summary>
        /// Authenticator can be contacted over a removable USB.
        /// </summary>
        public const string Usb = "usb";
        
        /// <summary>
        /// Authenticator can be contacted over Near Field Communication (NFC).
        /// </summary>
        public const string Nfc = "nfc";
        
        /// <summary>
        /// Authenticator can be contacted over Bluetooth Smart (Bluetooth Low Energy / BLE).
        /// </summary>
        public const string Ble = "ble";
        
        /// <summary>
        /// Authenticator can be contacted using a client device-specific transport (i.e. it is a platform authenticator).
        /// These authenticators are not removable from the device.
        /// </summary>
        public const string Internal = "internal";
    }

    /// <summary>
    /// Known attachment modalities.
    /// Values from <a href="https://www.w3.org/TR/webauthn-2/#enum-attachment">Authenticator Attachment Enumeration</a>.
    /// </summary>
    public static class AuthenticatorAttachment
    {
        /// <summary>
        /// Platform attachment using a client device-specific transport (i.e. it is a platform authenticator).
        /// These authenticators are not removable from the device.
        /// </summary>
        public const string Platform = "platform";

        /// <summary>
        /// Cross-platform attachment using a roaming authenticator that supports cross-platform transports.
        /// These authenticators can be removed from a device.
        /// </summary>
        public const string CrossPlatform = "cross-platform";
    }

    /// <summary>
    /// The relying party's requirement for client-side discoverable credentials (think usernameless authentication)
    /// Values from <a href="https://www.w3.org/TR/webauthn-2/#enum-residentKeyRequirement">Resident Key Requirement</a>.
    /// </summary>
    public static class ResidentKeyRequirement
    {
        /// <summary>
        /// Indicates the relying party prefers a server-side credential, but will accept a client-side discoverable credential.
        /// </summary>
        public const string Discouraged = "discouraged";
        
        /// <summary>
        /// Indicates the relying party strongly prefers a client-side discoverable credential but will accept a server-side credential.
        /// This takes precedence over the userVerification setting.
        /// </summary>
        public const string Preferred = "preferred";
        
        /// <summary>
        /// Indicates the relying party requires a client-side discoverable credential and will error if a client-side discoverable credential cannot be created.
        /// </summary>
        public const string Required = "required";
    }

    /// <summary>
    /// The relying party's requirement for user verification (e.g. a local PIN or biometric to use the authenticator).
    /// Values from <a href="https://www.w3.org/TR/webauthn-2/#enumdef-userverificationrequirement">User Verification Requirement</a>.
    /// </summary>
    public static class UserVerificationRequirement
    {
        /// <summary>
        /// Indicates the relying party requires user verification and will fail the operation if the UV flag is not set.
        /// </summary>
        public const string Required = "required";
        
        /// <summary>
        /// Indicates the relying party prefers user verification but will not fail the operation if the UV flag is not set.
        /// </summary>
        public const string Preferred = "preferred";
        
        /// <summary>
        /// Indicates the relying party does not want user verification to take place (e.g. to minimize disruption to UX).
        /// </summary>
        public const string Discouraged = "discouraged";
    }

    /// <summary>
    /// The relying party's preference for attestation conveyance.
    /// Values from <a href="https://www.w3.org/TR/webauthn-2/#enum-attestation-convey">AttestationConveyancePreference</a>.
    /// </summary>
    public static class AttestationConveyancePreference
    {
        /// <summary>
        /// Indicates the relying party is not interested in authenticator attestation.
        /// </summary>
        public const string None = "none";
        
        /// <summary>
        /// Indicates the relying party prefers attestation conveyance that provide verifiable attestation statements,
        /// but how they are obtained is up to the client (WebAuthn API).
        /// </summary>
        public const string Indirect = "indirect";
        
        /// <summary>
        /// Indicates the relying party wants to receive an attestation statement generated by the authenticator.
        /// </summary>
        public const string Direct = "direct";
        
        /// <summary>
        /// Indicates the relying party wants to receive an attestation statement that may include uniquely identifiable information.
        /// This is used when the authenticator is tied to an organization.
        /// </summary>
        public const string Enterprise = "enterprise";
    }
}