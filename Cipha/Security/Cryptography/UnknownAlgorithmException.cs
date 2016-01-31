using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Serialization;
using System.Text;
using System.Threading.Tasks;

namespace Cipha.Security.Cryptography
{
    [Serializable]
    public class UnknownAlgorithmException : Exception
    {
        public UnknownAlgorithmException() : base() { }
        public UnknownAlgorithmException(string message) : base(message) { }
        public UnknownAlgorithmException(string message, Exception inner) : base(message, inner) { }
    }
}
