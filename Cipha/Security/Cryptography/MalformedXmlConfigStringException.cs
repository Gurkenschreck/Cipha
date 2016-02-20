using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Cipha.Security.Cryptography
{
    internal class MalformedXmlConfigStringException : Exception
    {
        public MalformedXmlConfigStringException() : base() { }
        public MalformedXmlConfigStringException(string message) : base(message) { }
        public MalformedXmlConfigStringException(string message, Exception inner) : base(message, inner) { }
    }
}
