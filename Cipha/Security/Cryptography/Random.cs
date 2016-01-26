using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Cipha.Security.Cryptography
{
    public class Random
    {
        /// <summary>
        /// Fills an array of bytes with a cryptographically
        /// strong sequence of random bytes.
        /// 
        /// Makes use of the RNGCryptoServiceProvider.GetBytes
        /// method.
        /// </summary>
        /// <param name="randomBytes">The array to fill.</param>
        /// <returns>The random byte array.</returns>
        public void FillWithRandomBytes(byte[] randomBytes)
        {
            if (randomBytes == null)
                throw new ArgumentNullException("randomBytes");

            new RNGCryptoServiceProvider().GetBytes(randomBytes);
        }
    }
}
