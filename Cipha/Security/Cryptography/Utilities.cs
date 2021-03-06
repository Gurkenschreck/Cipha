﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Cipha.Security.Cryptography
{
    public class Utilities
    {
        /// <summary>
        /// Fills an array of bytes with a cryptographically
        /// strong sequence of random bytes.
        /// 
        /// Makes use of the RNGCryptoServiceProvider.GetBytes
        /// method.
        /// </summary>
        /// <param name="arrToFill">The array to fill.</param>
        /// <returns>The random byte array.</returns>
        public static void FillWithRandomBytes(byte[] arrToFill)
        {
            if (arrToFill == null)
                throw new ArgumentNullException("randomBytes");

            new RNGCryptoServiceProvider().GetBytes(arrToFill);
        }

        /// <summary>
        /// Generates a salt of n bytes using 
        /// RNGCryptoServiceProvider.
        /// </summary>
        /// <param name="amountOfBytes">The amount of bytes.</param>
        /// <returns>A strong salt</returns>
        public static byte[] GenerateBytes(int amountOfBytes)
        {
            byte[] salt = new byte[amountOfBytes];
            new RNGCryptoServiceProvider().GetBytes(salt);
            return salt;
        }

        /// <summary>
        /// Compares two byte arrays in length-constant time. This comparison
        /// method is used so that setupPassword hashes cannot be extracted from
        /// on-line systems using a timing attack and then attacked off-line.
        /// </summary>
        /// <param name="a">The first byte array.</param>
        /// <param name="b">The second byte array.</param>
        /// <returns>True if both byte arrays are equal. False otherwise.</returns>
        public static bool SlowEquals(byte[] a, byte[] b)
        {
            uint diff = (uint)a.Length ^ (uint)b.Length;
            for (int i = 0; i < a.Length && i < b.Length; i++)
                diff |= (uint)(a[i] ^ b[i]);
            return diff == 0;
        }

        /// <summary>
        /// Applies logical XOR on each byte of the provided array
        /// and returns the mirrored data.
        /// </summary>
        /// <param name="arrToFlip">The data to flip its bytes.</param>
        /// <returns>The exact opposite of arrToFlip.</returns>
        public static byte[] FlipBytes(byte[] arrToFlip)
        {
            byte[] flipped = (byte[])arrToFlip.Clone();
            for(int i = 0; i < flipped.Length; i++)
                flipped[i] = (byte)(flipped[i] ^ 255);
            return flipped;
        }

        /// <summary>
        /// Uses the ValidKeySize method implementation of
        /// the SymmetricAlgorithm class.
        /// </summary>
        /// <param name="algo">The symmetric algorithm to validate the size for.</param>
        /// <param name="bitLength">The requested block length in bits.</param>
        /// <returns>If the bitLenght is a valid block size.</returns>
        public static bool ValidSymmetricBlockSize(SymmetricAlgorithm algo, int bitLength)
        {
            KeySizes[] validSizes = algo.LegalBlockSizes;
            int i, j;

            if (validSizes == null) return false;
            for (i = 0; i < validSizes.Length; i++)
            {
                if (validSizes[i].SkipSize == 0)
                {
                    if (validSizes[i].MinSize == bitLength)
                    { // assume MinSize = MaxSize
                        return true;
                    }
                }
                else
                {
                    for (j = validSizes[i].MinSize; j <= validSizes[i].MaxSize;
                         j += validSizes[i].SkipSize)
                    {
                        if (j == bitLength)
                        {
                            return true;
                        }
                    }
                }
            }
            return false;
        }

        /// <summary>
        /// Overwrites each value with zeroes.
        /// </summary>
        /// <param name="arr">The array to wipe.</param>
        public static void SetArrayValuesZero(byte[] arr)
        {
            if (arr == null)
                throw new ArgumentNullException("byte array");
            if (arr.Length == 0)
                return;
            for (int i = 0; i < arr.Length; i++)
                arr[i] = 0;
        }

        /// <summary>
        /// Overwrites each value with zeroes.
        /// </summary>
        /// <param name="arr">The array to fill.</param>
        public static void SetArrayValuesZero(int[] arr)
        {
            if (arr == null)
                throw new ArgumentNullException("int array");
            if (arr.Length == 0)
                return;
            for (int i = 0; i < arr.Length; i++)
                arr[i] = 0;
        }

        /// <summary>
        /// Overwrites each value with string.Empty.
        /// </summary>
        /// <param name="arr">The array to fill.</param>
        public static void SetArrayValuesEmpty(string[] arr)
        {
            if (arr == null)
                throw new ArgumentNullException("string array");
            if (arr.Length == 0)
                return;
            for (int i = 0; i < arr.Length; i++)
                arr[i] = string.Empty;
        }
    }
}
