using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Cipha.Security.Cryptography.Hash
{
    public class Hasher<T> : IDisposable
        where T : HashAlgorithm, new()
    {
        protected T algo;
        protected bool disposeAlgorithm = true;
        protected Encoding encoding = Encoding.UTF8;

        /// <summary>
        /// Gets or sets the hashalgorithm to use.
        /// </summary>
        public T Algorithm
        {
            get
            {
                return algo;
            }
            set
            {
                algo = value;
            }
        }
        /// <summary>
        /// Gets or sets the encoding used to convert the input strings
        /// of the methods.
        /// </summary>
        public Encoding Encoding
        {
            get { return encoding; }
            set { encoding = value; }
        }

        // Decorator
        /// <summary>
        /// Gets the input block size.
        /// </summary>
        public int InputBlockSize
        {
            get
            {
                return algo.InputBlockSize;
            }
        }
        /// <summary>
        /// Gets the output block size.
        /// </summary>
        public int OutputBlockSize
        {
            get
            {
                return algo.OutputBlockSize;
            }
        }
        /// <summary>
        /// Gets the size (in bits) of the hash.
        /// </summary>
        public int HashSize
        {
            get
            {
                return algo.HashSize;
            }
        }
        /// <summary>
        /// Gets the last computed hash.
        /// </summary>
        public byte[] LastHash
        {
            get
            {
                return algo.Hash;
            }
        }

        /// <summary>
        /// Creates a new instance of the algorithm.
        /// </summary>
        public Hasher()
        {
            algo = new T();
        }
        /// <summary>
        /// Applies the reference of the passed algorithm.
        /// </summary>
        /// <param name="refAlgo">The reference to use.</param>
        /// <param name="disposeAlgorithm">If true, the reference 
        /// object is also disposed when the symmetricCipher is disposed.</param>
        public Hasher(T refAlgo, bool disposeAlgorithm = false)
        {
            if (refAlgo == null)
                throw new ArgumentNullException("refAlgo");
            algo = refAlgo;
            this.disposeAlgorithm = disposeAlgorithm;
        }

        /// <summary>
        /// Hashes a stream and returns the related hash digest.
        /// </summary>
        /// <param name="dataStream">The stream to hash.</param>
        /// <returns>The hash of the stream.</returns>
        public byte[] Hash(Stream dataStream)
        {
            return algo.ComputeHash(dataStream);
        }
        /// <summary>
        /// Hashes a string and returns the related hash digest.
        /// </summary>
        /// <param name="stringToHash">The string to hash. The string is decoded with the set Encoding.</param>
        /// <param name="rounds">The amout of hash rounds.</param>
        /// <returns>The hash after N rounds.</returns>
        public byte[] Hash(string stringToHash, int rounds = 1)
        {
            return Hash(encoding.GetBytes(stringToHash), rounds);
        }
        /// <summary>
        /// Hashes a string.
        /// </summary>
        /// <param name="dataToHash">The data to hash.</param>
        /// <returns>The hash of the data.</returns>
        public byte[] Hash(byte[] dataToHash)
        {
            return Hash(dataToHash, 1);
        }
        /// <summary>
        /// Hashes a specific region of the data.
        /// </summary>
        /// <param name="dataToHash">The data to hash a part of.</param>
        /// <param name="offSet">The start byte index.</param>
        /// <param name="length">The amount of bytes to extract.</param>
        /// <returns>The hash of the specified region.</returns>
        public byte[] Hash(byte[] dataToHash, int offSet, int length)
        {
            byte[] wannabeHash = new byte[length];
            Array.Copy(dataToHash, offSet, wannabeHash, 0, length);
            return Hash(wannabeHash, 1);
        }
        /// <summary>
        /// Hashes the given data a total of N times.
        /// </summary>
        /// <param name="dataToHash">The data to hash.</param>
        /// <param name="rounds">The amount of hashing rounds.</param>
        /// <returns>The hash of the data after N iterations.</returns>
        public byte[] Hash(byte[] dataToHash, int rounds)
        {
            if (dataToHash == null)
                throw new ArgumentNullException("dataToHash");
            if (rounds < 1)
                throw new ArgumentOutOfRangeException("rounds cannot be < 1");

            byte[] hash = algo.ComputeHash(dataToHash);

            for (int i = 1; i < rounds; i++)
                hash = algo.ComputeHash(hash);

            return hash;
        }

        /// <summary>
        /// Hashes a string and converts the hash
        /// to a base64 string.
        /// </summary>
        /// <param name="stringToHash">The string to hash.</param>
        /// <returns>The base64 converted string.</returns>
        public string HashToString(string stringToHash)
        {
            return HashToString(stringToHash, 1);
        }
        /// <summary>
        /// Hashes a string a number of N times.
        /// Decodes the provided string using the
        /// specified Encoding.
        /// </summary>
        /// <param name="stringToHash">The string to hash.</param>
        /// <param name="rounds">The amount of hash rounds.</param>
        /// <returns>The base64 hash after N rounds.</returns>
        public string HashToString(string stringToHash, int rounds)
        {
            return HashToString(encoding.GetBytes(stringToHash), rounds);
        }
        /// <summary>
        /// Hashes data and returns a base64 representation
        /// of the hash.
        /// </summary>
        /// <param name="dataToHash">The data to hash.</param>
        /// <returns>The base64 hash string.</returns>
        public string HashToString(byte[] dataToHash)
        {
            return HashToString(dataToHash, 1);
        }
        /// <summary>
        /// Hashes data a number of N times.
        /// Returns a base64 string representation
        /// of the hash.
        /// </summary>
        /// <param name="dataToHash">The data to hash.</param>
        /// <param name="rounds">The amount of hash rounds.</param>
        /// <returns>The base64 hash string.</returns>
        public string HashToString(byte[] dataToHash, int rounds)
        {
            return Convert.ToBase64String(Hash(dataToHash, rounds));
        }

        /// <summary>
        /// Hashes the provided string to validate and compares it
        /// to the provided base64 hash string.
        /// </summary>
        /// <param name="stringToValidate">The string to hash.</param>
        /// <param name="givenHash">The hash.</param>
        /// <returns>If the hash of the string is equal to the provided hash.</returns>
        public bool VerifyHash(string stringToValidate, string givenHash)
        {
            return VerifyHash(encoding.GetBytes(stringToValidate), Convert.FromBase64String(givenHash));
        }
        /// <summary>
        /// Hashes the provided string to validate and compares it
        /// to the provided hash.
        /// </summary>
        /// <param name="stringToValidate">The string to validate.</param>
        /// <param name="givenHash">The hash.</param>
        /// <returns>If the hash of the string is equal to the provided hash.</returns>
        public bool VerifyHash(string stringToValidate, byte[] givenHash)
        {
            return VerifyHash(encoding.GetBytes(stringToValidate), givenHash);
        }
        /// <summary>
        /// Hashes the provided data to validate and compares it
        /// to the provided hash.
        /// </summary>
        /// <param name="dataToValidate">The data to hash.</param>
        /// <param name="givenHash">The hash.</param>
        /// <returns>If the hash of the data is equal to the provided hash.</returns>
        public bool VerifyHash(byte[] dataToValidate, byte[] givenHash)
        {
            return Hash(dataToValidate).SequenceEqual(givenHash);
        }
        // Dispose implementation
        ~Hasher()
        {
            Dispose(false);
        }
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool isDisposing)
        {
            if(isDisposing)
            {
                if(disposeAlgorithm)
                    algo.Dispose();
                algo = null;
            }
        }
    }
}
