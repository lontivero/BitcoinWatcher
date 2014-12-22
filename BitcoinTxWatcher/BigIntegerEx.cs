using System;
using Org.BouncyCastle.Math;

namespace BitcoinTxWatcher
{
    static class BigIntegerEx
    {
        static public BigInteger FromByteArray(byte[] bytes)
        {
            var buf = new byte[bytes.Length + 1];
            Buffer.BlockCopy(bytes, 0, buf, 1, bytes.Length);

            return new BigInteger(buf);
        }
    }
}