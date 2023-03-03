namespace ScottBrady.Fido2.Cryptography;

/// <summary>
/// Values from the <a href="https://www.iana.org/assignments/cose/cose.xhtml">COSE IANA registry</a>.
/// </summary>
public static class CoseConstants
{
    // https://www.iana.org/assignments/cose/cose.xhtml#key-common-parameters
    // https://www.iana.org/assignments/cose/cose.xhtml#key-type-parameters
    public static class Parameters
    {
        public const string Kty = "1";
        public const string Kid = "2";
        public const string Alg = "3";

        public const string Crv = "-1";
        public const string X = "-2";
        public const string Y = "-3";

        public const string N = "-1";
        public const string E = "-2";
    }

    // https://www.iana.org/assignments/cose/cose.xhtml#key-type
    public static class KeyTypes
    {
        public const string Okp = "1";
        public const string Ec2 = "2";
        public const string Rsa = "3";
        public const string Symmetric = "4";
        public const string HssLms = "5";
        public const string WalnutDsa = "6";
    }

    // https://www.iana.org/assignments/cose/cose.xhtml#algorithms
    public static class Algorithms
    {
        public const string ES256 = "-7";
        public const string EdDSA = "-8";
        public const string ES384 = "-35";
        public const string ES512 = "-36";
        public const string ES256K = "-47";
        public const string RS256 = "-257";
        public const string RS384 = "-258";
        public const string RS512 = "-259";
        public const string RS1 = "-65535";
    }

    // https://www.iana.org/assignments/cose/cose.xhtml#elliptic-curves
    public static class EllipticCurves
    {
        public const string P256 = "1";
        public const string P384 = "2";
        public const string P521 = "3";
        public const string X25519 = "4";
        public const string X448 = "5";
        public const string Ed25519 = "6";
        public const string Ed448 = "7";
        public const string Secp256k1 = "8";
    }
}