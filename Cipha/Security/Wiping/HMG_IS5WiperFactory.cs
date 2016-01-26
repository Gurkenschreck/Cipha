using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Cipha.Security.Wiping
{
    public class HMG_IS5WiperFactory : WiperFactory
    {
        public override Wiper CreateWiper()
        {
            return CreateWiper(true);
        }
        public HMG_IS5Wiper CreateWiper(bool enhanced)
        {
            return new HMG_IS5Wiper() { Enhanced = enhanced };
        }
    }
}
