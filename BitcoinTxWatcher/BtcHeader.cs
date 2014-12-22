using System;
using System.IO;
using Open.Sniffer;

namespace BitcoinTxWatcher
{
    public class BtcHeader
    {
        public BtcHeader(TcpHeader tcpHeader)
        {
            TcpHeader = tcpHeader;
            using (var memr = new MemoryStream(tcpHeader.Data.Array, tcpHeader.Data.Offset, tcpHeader.Data.Count))
            {
                using (var reader = new BinaryReader(memr))
                {
                    Magic = reader.ReadUInt32();
                    Command = new String(reader.ReadChars(12));
                    Length = reader.ReadUInt32();
                    Checksum = reader.ReadUInt32();
                    Payload = new ArraySegment<byte>(tcpHeader.Data.Array, tcpHeader.Data.Offset + 24, (int)Length);
                }
            }
        }

        public ArraySegment<byte> Payload { get; private set; }
        public uint Checksum { get; private set; }
        public uint Length { get; private set; }
        public string Command { get; private set; }
        public uint Magic { get; private set; }
        public TcpHeader TcpHeader { get; private set; }
    }
}