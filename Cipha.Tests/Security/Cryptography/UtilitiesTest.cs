using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Cipha.Security.Cryptography;

namespace Cipha.Tests.Security.Cryptography
{
    [TestClass]
    public class UtilitiesTest
    {
        [TestMethod]
        public void SetIntValuesZero_ValuesChange_ComparesZeroes()
        {
            byte[] arr = {
                             1,2,3,4,5,6,7,8,9,0
                         };
            byte[] finalArr = {
                                  0,0,0,0,0,0,0,0,0,0
                              };

            Utilities.SetArrayValuesNull(arr);

            Assert.IsTrue(Utilities.SlowEquals(finalArr, arr));
        }
    }
}
