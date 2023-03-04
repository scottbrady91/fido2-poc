using System;

namespace ScottBrady.Fido2;

public class FidoException : Exception
{
    public FidoException() { }

    public FidoException(string message) : base(message) { }

    public FidoException(string message, Exception inner) : base(message, inner) { }
}