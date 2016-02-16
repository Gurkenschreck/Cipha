using System;
using System.Collections.Generic;
using System.Linq;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Cipha.Security.Cryptography;

namespace Cipha.Security.Cryptography.Hash
{
    /// <summary>
    /// GenericHasher provides an interface to
    /// interact with all classes deriving from
    /// System.Security.Cryptography.HashAlgoritm.
    /// 
    /// Possible classes include, but are not limited to:
    ///     RIPEMD160Managed
    ///     SHA1Managed
    ///     SHA2Managed
    ///     SHA256Managed
    ///     SHA384Managed
    ///     SHA512Managed
    ///     MD5CryptoServiceProvider
    ///     
    /// located in the System.Security.Cryptography namespace.
    /// </summary>
    /// <typeparam name="T">A concrete hash algorithm deriving from HashAlg</typeparam>
    public class GenericHasher<T>
        where T : HashAlgorithm, new()
    {
        private Encoding encoding = Encoding.UTF8;
        /// <summary>
        /// The encoding which should be used.
        /// </summary>
        public Encoding Encoding
        {
            get { return encoding; }
            set
            {
                if (value == null)
                    throw new InvalidOperationException("encoding cannot be set to null");
                encoding = value;
            }
        }

        /// <summary>
        /// Computes a hash of the given string and
        /// returns the hash as a base64 string.
        /// </summary>
        /// <param name="stringToHash">The string to hash.</param>
        /// <returns>The hash as a base64 string.</returns>
        public string ComputeHashToString(string stringToHash)
        {
            return ComputeHashToString(encoding.GetBytes(stringToHash));
        }

        /// <summary>
        /// Computes a hash of the given byte array and
        /// returns the hash as a base64 string.
        /// </summary>
        /// <param name="bytesToHash">The data to hash.</param>
        /// <returns>The hash as a base64 string.</returns>
        public string ComputeHashToString(byte[] bytesToHash)
        {
            return Convert.ToBase64String(ComputeHash(bytesToHash));
        }

        /// <summary>
        /// Computes a hash of the given string
        /// and returns the hash as a string with
        /// the specified encoding.
        /// </summary>
        /// <param name="stringToHash">The string to hash.</param>
        /// <returns>The normal string</returns>
        public byte[] ComputeHash(string stringToHash)
        {
            return ComputeHash(encoding.GetBytes(stringToHash));
        }

        /// <summary>
        /// Computes a hash of the given byte array
        /// and returns the hash as a byte array.
        /// </summary>
        /// <param name="dataToHash">The data to hash.</param>
        /// <returns>The hashed values.</returns>
        public byte[] ComputeHash(byte[] dataToHash)
        {
            byte[] hashedValues = null;
            using(HashAlgorithm algo = new T())
            {
                hashedValues = algo.ComputeHash(dataToHash);
            }
            return hashedValues;
        }

        public byte[] ComputeHash(byte[] dataToHash, int iterationCount)
        {
            if (dataToHash == null)
                throw new ArgumentNullException("dataToHash");
            if (iterationCount < 1)
                throw new ArgumentOutOfRangeException("iterationCount must be > 0");

            byte[]  hashedValue = null;
            using(var algo = new T())
            {
                hashedValue = algo.ComputeHash(dataToHash); // initial hash

                for (int i = 1; i < iterationCount; i++) // hash the hashed values n times
                    hashedValue = algo.ComputeHash(hashedValue);
            }
            return hashedValue;
            //return ComputeHash(dataToHash, new byte[] {}, iterationCount);
        }
        public byte[] ComputeHash(byte[] dataToHash, byte[] salt, int iterationCount)
        {
            if (dataToHash == null)
                throw new ArgumentNullException("dataToHash");
            if (salt == null)
                throw new ArgumentNullException("salt");
            if (iterationCount < 1)
                throw new ArgumentOutOfRangeException("iterationCount must be > 0");


            byte[] combi = null;

                combi = new byte[dataToHash.Length + salt.Length];
                dataToHash.CopyTo(combi, 0);
                salt.CopyTo(combi, dataToHash.Length);

            byte[] hashedValue = null;
            using (var algo = new T())
            {

                hashedValue = algo.ComputeHash(combi); // initial hash

                for (int i = 1; i < iterationCount; i++) // hash the hashed values n times
                    hashedValue = algo.ComputeHash(hashedValue);
            }
            return hashedValue;
        }

        /// <summary>
        /// Computes 2 hashes of the strings and
        /// compare them bitwise.
        /// </summary>
        /// <param name="stringA">String A to hash.</param>
        /// <param name="stringB">String B to hash.</param>
        /// <returns>If both hashes are equal.</returns>
        public bool ComputeAndCompare(string stringA, string stringB)
        {
            return AreHashesEqual(ComputeHash(stringA), ComputeHash(stringB));
        }

        /// <summary>
        /// Computes 2 hashes of the provided byte
        /// arrays and compare them bitwise.
        /// </summary>
        /// <param name="dataA">Data A to hash.</param>
        /// <param name="dataB">Data B to hash.</param>
        /// <returns></returns>
        public bool ComputeAndCompare(byte[] dataA, string dataB)
        {
            return AreHashesEqual(ComputeHash(dataA), ComputeHash(dataB));
        }

        /// <summary>
        /// Iterates through the byte arrays and comparing bitwise
        /// if the values of the arrays are equal.
        /// </summary>
        /// <param name="hashA">The first byte array.</param>
        /// <param name="hashB">The second byte array.</param>
        /// <returns>If both hashes are equal.</returns>
        public bool AreHashesEqual(byte[] hashA, byte[] hashB)
        {
            return hashA.SequenceEqual(hashB);
        }

        /// <summary>
        /// Computes a hash and transforms it to a hex string.
        /// </summary>
        /// <param name="stringToHash">The string to hash.</param>
        /// <param name="useLowercase">If the hex string should contain lowercase or uppercase letters.</param>
        /// <returns>The hex string.</returns>
        public string ComputeHashToHex(string stringToHash, bool useLowercase)
        {
            byte[] inputBytes = encoding.GetBytes(stringToHash);
            byte[] hash = ComputeHash(inputBytes);

            return HashToHex(hash, useLowercase);
        }

        /// <summary>
        /// Converts a given hash to a hex string.
        /// </summary>
        /// <param name="hashedBytes">The already hashed data.</param>
        /// <param name="useLowercase">If the hex string should contain lowercase or uppercase letters.</param>
        /// <returns>The hex string.</returns>
        public string HashToHex(byte[] hashedBytes, bool useLowercase)
        {
            // step 2, convert byte array to hex string
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < hashedBytes.Length; i++)
            {
                if (useLowercase)
                    sb.Append(hashedBytes[i].ToString("x2"));
                else
                    sb.Append(hashedBytes[i].ToString("X2"));
            }
            return sb.ToString();
        }
    }
}
