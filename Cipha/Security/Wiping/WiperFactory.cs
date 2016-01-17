using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Cipha.Security.Wiping
{
    public abstract class WiperFactory
    {
        public abstract Wiper CreateWiper();
    }
}
