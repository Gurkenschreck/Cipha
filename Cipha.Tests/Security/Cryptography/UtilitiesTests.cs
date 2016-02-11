using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Cipha.Security.Cryptography;

namespace Cipha.Tests.Security.Cryptography
{
    [TestClass]
    public class UtilitiesTests
    {
        [TestMethod]
        public void SlowEquals_CompareArrays_Pass()
        {
            byte[] arr = {
                             1,2,3,4,5,6,7,8,9,0
                         };
            byte[] finalArr = {
                                  0,0,0,0,0,0,0,0,0,0
                              };

            Utilities.SetArrayValuesZero(arr);

            Assert.IsTrue(Utilities.SlowEquals(finalArr, arr));
        }

        [TestMethod]
        public void SetArrayValuesZero_WipeIntArray_Pass()
        {
            int[] arr = {
                             1,2,3,4,5,6,7,8,9,0
                         };
            int[] finalArr = {
                                  0,0,0,0,0,0,0,0,0,0
                              };

            Utilities.SetArrayValuesZero(arr);

            CollectionAssert.AreEqual(finalArr, arr);
        }
        [TestMethod]
        public void SetByteArrayValuesZero_WipeIntArray_Pass()
        {
            byte[] arr = {
                             1,2,3,4,5,6,7,8,9,0
                         };
            byte[] finalArr = {
                                  0,0,0,0,0,0,0,0,0,0
                              };

            Utilities.SetArrayValuesZero(arr);

            CollectionAssert.AreEqual(finalArr, arr);
        }
        [ExpectedException(typeof(ArgumentNullException))]
        [TestMethod]
        public void SetByteArrayValuesZero_PassNullArray_FailArgumentNullException()
        {
            byte[] arr = null;

            Utilities.SetArrayValuesZero(arr);
        }

        [TestMethod]
        public void SetArrayValuesEmpty_WipeStringArray_Pass()
        {
            string[] arr = {
                            "hello", "my", "friend"
                            };
            string[] finalArr = {
                                  "", "", ""
                              };

            Utilities.SetArrayValuesEmpty(arr);

            CollectionAssert.AreEqual(finalArr, arr);
        }
        [TestMethod]
        public void FillWithRandomBytes_GenerateBytes_PassNotEqual()
        {
            byte[] bytes1 = new byte[20];
            byte[] bytes2 = new byte[20];

            Utilities.FillWithRandomBytes(bytes1);
            Utilities.FillWithRandomBytes(bytes2);

            Assert.AreNotEqual(bytes1, bytes2);
        }
        [ExpectedException(typeof(ArgumentNullException))]
        [TestMethod]
        public void FillWithRandomBytes_GenerateBytes_ArgumentNullExceptionFail()
        {
            byte[] bytes1 = null;

            Utilities.FillWithRandomBytes(bytes1);
        }
        [TestMethod]
        public void FlipBytes_FlipAllZeroesOfArray_Pass()
        {
            byte[] bytes = {0,0,0,0,0,0,0,0,0,0};
            byte[] flipped = { 255, 255, 255, 255, 255, 255, 255, 255, 255, 255 };
            byte[] functionFlipped = Utilities.FlipBytes(bytes);
            CollectionAssert.AreEqual(flipped, functionFlipped);
        }
        [TestMethod]
        public void FlipBytes_FlipSmallArray_Pass()
        {
            byte[] bytes = { 0, 3 };
            byte[] flipped = { 255, 252 };
            byte[] functionFlipped = Utilities.FlipBytes(bytes);
            CollectionAssert.AreEqual(flipped, functionFlipped);
        }
        [ExpectedException(typeof(ArgumentNullException))]
        [TestMethod]
        public void SetArrayValuesEmpty_PassNull_ArgumentNullException()
        {
            string[] nullarr = null;
            Utilities.SetArrayValuesEmpty(nullarr);
        }
    }
}
