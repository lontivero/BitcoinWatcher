using System.Collections.Generic;
using Org.BouncyCastle.Math;

namespace BitcoinTxWatcher
{
    internal class Output
    {
        public byte ScriptLength;
        public long Value;
        public byte[] Script;
    }

    internal class Input
    {
        public byte[] Previous;
        public long ScriptLength;
        public byte[] Script;
        public byte[] rawR;
        public byte HashType;
        public byte[] PublicKey;
        public int Seq;
        public BigInteger m;
        public byte[] rawS;
        public int PreviousSeq;

        public BigInteger M
        {
            set { m = value; }
            get
            {
                return m ?? BigInteger.Zero;
            }
        }

        public BigInteger S
        {
            get
            {
                return BigIntegerEx.FromByteArray(rawS);
            }
        }
        public BigInteger R
        {
            get
            {
                return BigIntegerEx.FromByteArray(rawR);
            }
        }
    }

    internal class Tx
    {
        public int Version;
        public List<Input> Inputs;
        public List<Output> Outputs;
        public int Locktime;
    }
}
