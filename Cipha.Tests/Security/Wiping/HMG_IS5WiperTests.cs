using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.IO;
using Cipha.Security.Wiping;

namespace Cipha.Tests.Security.Wiping
{
    [TestClass]
    public class HMG_IS5WiperTests
    {
        [TestMethod]
        public void WipeStream_WipeRandomStream_Pass()
        {
            MemoryStream stream = new MemoryStream();

            for (int i = 0; i < 100; i++)
                stream.WriteByte(0x1F);

            var fact = new HMG_IS5WiperFactory();
            HMG_IS5Wiper wiper = (HMG_IS5Wiper)fact.CreateWiper(true);

            wiper.WipeStream(stream);

            Assert.IsTrue(stream.Length == 0);
        }
    }

    [TestClass]
    public class HMG_IS5WiperFactoryTests
    {
        [TestMethod]
        public void CreateWiper_InstantiateNew_Pass()
        {
            HMG_IS5WiperFactory fact = new HMG_IS5WiperFactory();
            HMG_IS5Wiper wiper = (HMG_IS5Wiper)fact.CreateWiper(); 

            Assert.IsNotNull(wiper);
        }
        [TestMethod]
        public void CreateWiper_InstantiateNewEnhanced_Pass()
        {
            HMG_IS5WiperFactory fact = new HMG_IS5WiperFactory();
            HMG_IS5Wiper wiper = (HMG_IS5Wiper)fact.CreateWiper(true);

            Assert.IsTrue(wiper.Enhanced);
        }
    }
}
