using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Cipha.Security.Cryptography
{
    [Serializable]
    public class CipherConfig : IDisposable
    {
        // Properties
        AlgorithmType type;
        internal AlgorithmType Type
        {
            get { return type; }
        }

        int keySize;
        public int KeySize
        {
            get { return keySize; }
        }

        int blockSize;
        public int BlockSize
        {
            get { return blockSize; }
        }

        byte[] iv;
        public byte[] IV
        {
            get { return iv; }
        }

        byte[] key;
        public byte[] Key
        {
            get { return key; }
        }

        int feedbackSize;
        public int FeedbackSize
        {
            get { return feedbackSize; }
        }

        int hashIterations = 1000;
        public int HashIterations
        {
            get { return hashIterations; }
        }

        byte[] salt;
        public byte[] Salt
        {
            get { return salt; }
        }


        // Constructors
        public CipherConfig(AlgorithmType type, byte[] key, byte[] iv, int keySize, int blockSize, byte[] salt = null)
        {
            this.type = type;
            this.key = key;
            this.iv = iv;
            this.keySize = keySize;
            this.blockSize = blockSize;
            this.salt = null;
        }

        /// <summary>
        /// Clones the values of an SymmetricAlgorithm.
        /// </summary>
        /// <param name="algorithm">The algorithm to clone its values</param>
        public CipherConfig(SymmetricAlgorithm algorithm)
        {
            this.type = AlgorithmType.Symmetric;
            this.key = algorithm.Key;
            this.iv = algorithm.IV;
            this.blockSize = algorithm.BlockSize;
            this.keySize = algorithm.KeySize;
            this.feedbackSize = algorithm.FeedbackSize;
        }

        /// <summary>
        /// Clones the values of an AsymmetricAlgorithm.
        /// </summary>
        /// <param name="algorithm">Any AsymmetricAlgorithm.</param>
        /// <param name="includePrivateKey">If it is true, it also exports the private key of the algorithm. If false only the public.</param>
        public CipherConfig(AsymmetricAlgorithm algorithm, bool includePrivateKey)
        {
            this.type = AlgorithmType.Asymmetric;
            this.key = Convert.FromBase64String(algorithm.ToXmlString(includePrivateKey));
            this.keySize = algorithm.KeySize;
        }

        ~CipherConfig()
        {
            Dispose(false);
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Release all ressources.
        /// </summary>
        /// <param name="disposing">If the call comes from local Dispose() method.</param>
        protected void Dispose(bool disposing)
        {
            if(disposing)
            {
                Utilities.SetArrayValuesZero(iv);
                Utilities.SetArrayValuesZero(key);
                Utilities.SetArrayValuesZero(salt);  

                iv = null;
                key = null;
                salt = null;
                keySize = 0;
                blockSize = 0;
                hashIterations = 0;
                type = AlgorithmType.NotSpecified;
            }
        }
    }
}
