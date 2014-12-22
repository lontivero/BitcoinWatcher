using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace BitcoinTxWatcher
{
    static class StringExtensions
    {
        public static byte[] ToByteArray(this string str)
        {
            var y = Enumerable.Range(0, str.Length)
                .Where(x => x % 2 == 0)
                .Select(x => Convert.ToByte(str.Substring(x, 2), 16))
                .ToArray();
            return y;
        }

        public static string ToHex(this IEnumerable<byte> ba)
        {
            var enumerable = ba as byte[] ?? ba.ToArray();
            var hex = new StringBuilder(enumerable.Length * 2);
            foreach (var b in enumerable)
                hex.AppendFormat("{0:x2}", b);
            return hex.ToString();
        }
    }
}