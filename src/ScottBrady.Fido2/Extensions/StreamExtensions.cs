using System;
using System.IO;

namespace ScottBrady.Fido2;

/// <summary>
/// Adapted from ScottBrady.IdentityModel.
/// </summary>
public static class StreamExtensions
{
    public static byte[] ReadBytes(this Stream stream, int length)
    {
        var bytes = new byte[length];
        var bytesRead = stream.Read(bytes, 0, length);

        // TODO: exceptions
        if (bytesRead != length) throw new Exception();
        return bytes;
    }
}