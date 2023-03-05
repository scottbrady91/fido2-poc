using System.IO;

namespace ScottBrady.Fido2;

/// <summary>
/// Helper methods adapted from ScottBrady.IdentityModel.
/// </summary>
public static class StreamExtensions
{
    /// <summary>
    /// Read the requested amount of bytes from the current stream.  
    /// </summary>
    /// <exception cref="FidoException">Bytes read do not match requested length</exception>
    public static byte[] ReadBytes(this Stream stream, int length)
    {
        var bytes = new byte[length];
        var bytesRead = stream.Read(bytes, 0, length);

        // TODO: improve this exception when reading bytes...
        if (bytesRead != length) throw new FidoException("Unable to read bytes (invalid length)");
        return bytes;
    }
}