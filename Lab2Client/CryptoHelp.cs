using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Lab2Client
{
    class CryptoHelp
    {
        public static byte[] GetEncryptedMessage(byte[] sessionKey, string msg)
        {
            Random rng = new Random((int)DateTime.Now.Ticks);
            List<byte> bytes = new List<byte>();
            AesCcm aesCcm = new AesCcm(sessionKey);
            byte[] nonce = new byte[AesCcm.NonceByteSizes.MaxSize];
            rng.NextBytes(nonce);
            byte[] plainText = Encoding.ASCII.GetBytes(msg);
            byte[] cypherText = new byte[plainText.Length];
            byte[] tag = new byte[AesCcm.TagByteSizes.MaxSize];
            aesCcm.Encrypt(nonce, plainText, cypherText, tag);
            int size = 4 + nonce.Length + tag.Length + 4 + cypherText.Length;
            bytes.AddRange(BitConverter.GetBytes(size));
            bytes.AddRange(nonce);
            bytes.AddRange(tag);
            bytes.AddRange(BitConverter.GetBytes(msg.Length));
            bytes.AddRange(cypherText);
            return bytes.ToArray();
        }

        public static string GetDecryptedMessage(byte[] sessionKey, byte[] totalResponse)
        {
            AesCcm aesCcm = new AesCcm(sessionKey);
            int msgSize = BitConverter.ToInt32(totalResponse[(AesCcm.NonceByteSizes.MaxSize + AesCcm.TagByteSizes.MaxSize)..(AesCcm.NonceByteSizes.MaxSize + AesCcm.TagByteSizes.MaxSize + 4)]);
            byte[] decryptedMessage = new byte[msgSize];
            aesCcm.Decrypt(
                totalResponse[..AesCcm.NonceByteSizes.MaxSize],
                totalResponse[(AesCcm.NonceByteSizes.MaxSize + AesCcm.TagByteSizes.MaxSize + 4)..(AesCcm.NonceByteSizes.MaxSize + AesCcm.TagByteSizes.MaxSize + 4 + msgSize)],
                totalResponse[AesCcm.NonceByteSizes.MaxSize..(AesCcm.NonceByteSizes.MaxSize + AesCcm.TagByteSizes.MaxSize)],
                decryptedMessage
            );
            return Encoding.ASCII.GetString(decryptedMessage);
        }
    }
}
