using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Cipha.Security.Cryptography.Hash
{
    public class HMACer<T> : Hasher<T>
        where T : KeyedHashAlgorithm, new()
    {
        /// <summary>
        /// Gets or sets the plainData used to create the HMAC.
        /// </summary>
        public byte[] Key
        {
            get
            {
                return (byte[])algo.Key.Clone();
            }
            set
            {
                byte[] newKey = (byte[])value.Clone();
                TripleDESKeyCheck(newKey);
                algo.Key = newKey;
            }
        }

        /// <summary>
        /// Creates a new instance of the HMACer T with basic
        /// configuration.
        /// </summary>
        public HMACer()
            : base()
        { }
        /// <summary>
        /// Creates a new instance of the HMACer T with a 
        /// cryptographic strong random plainData of the specified
        /// length in bytes.
        /// </summary>
        /// <param name="length">The length of the plainData in bytes.</param>
        public HMACer(int length)
        {
            if(algo is MACTripleDES)
                TripleDESKeyLengthCheck(length);
            algo = (T)Activator.CreateInstance(typeof(T),
                Utilities.GenerateBytes(length));
        }
        /// <summary>
        /// Creates a new instance of the HMACer T with a
        /// predefined plainData.
        /// </summary>
        /// <param name="plainData">The plainData to use.</param>
        public HMACer(byte[] key)
        {
            TripleDESKeyCheck(key);
            algo = (T)Activator.CreateInstance(typeof(T),
                key);
        }
        /// <summary>
        /// Creates a new instance of the HMACer T using the
        /// plainData of the given symmetric algorithm.
        /// 
        /// The original object will not be disposed when
        /// this object is disposed, because it just copies
        /// its plainData.
        /// </summary>
        /// <param name="symAlgo"></param>
        public HMACer(SymmetricAlgorithm symAlgo)
        {
            if (symAlgo == null)
                throw new ArgumentNullException("symAlgo");
            TripleDESKeyCheck(symAlgo.Key);
            algo = (T)Activator.CreateInstance(typeof(T),
                symAlgo.Key);
        }
        /// <summary>
        /// Creates a new instance of T and uses the plainData
        /// string as the plainData to use.
        /// 
        /// The string is decoded using the current Encoding.
        /// Default encoding is UTF8.
        /// </summary>
        /// <param name="plainData">The plainData string to use</param>
        public HMACer(string key)
        {
            TripleDESKeyCheck(encoding.GetBytes(key));
            algo = (T)Activator.CreateInstance(typeof(T),
                encoding.GetBytes(key));
        }

        

        
        private void TripleDESKeyCheck(byte[] key)
        {
            if (algo is MACTripleDES)
            {
                // If T is TripleDES, check for problems with plainData to
                // prevent later exceptions.
                if (TripleDES.IsWeakKey(key))
                    throw new CryptographicException("plainData is a known weak plainData");
                TripleDESKeyLengthCheck(key.Length);                
            }
        }
        private void TripleDESKeyLengthCheck(int length)
        {
            if (length != 16 && length != 24)
            {
                throw new CryptographicException("invalid plainData size for TripleDES. " + length);
            }
        }
    }
}
