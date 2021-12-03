using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace Lab2Client
{
    class Client
    {
        public static Socket _server;
        public static ECCurve curve;
        public static ECDsa ecdsaKey;
        public static ECDiffieHellman ecdhKey;
        public static byte[] sessionKey;
        public static void StartClient()
        {
            try
            {
                IPHostEntry ipHostInfo = Dns.GetHostEntry(Dns.GetHostName());
                IPAddress ipAddress = ipHostInfo.AddressList[0];
                IPEndPoint remoteEP = new IPEndPoint(ipAddress, 11000);

                _server = new Socket(ipAddress.AddressFamily,
                    SocketType.Stream, ProtocolType.Tcp);
 
                try
                {
                    _server.Connect(remoteEP);

                    Console.WriteLine("Socket connected to {0}",
                        _server.RemoteEndPoint.ToString());
                }
                catch (ArgumentNullException ane)
                {
                    Console.WriteLine("ArgumentNullException : {0}", ane.ToString());
                }
                catch (SocketException se)
                {
                    Console.WriteLine("SocketException : {0}", se.ToString());
                }
                catch (Exception e)
                {
                    Console.WriteLine("Unexpected exception : {0}", e.ToString());
                }

            }
            catch (Exception e)
            {
                Console.WriteLine(e.ToString());
            }
        }

        public static void SendRequest(string request)
        {
            byte[] message = Encoding.ASCII.GetBytes(request);
            _server.Send(message);
        }

        public static void StopClient()
        {
            try
            {
                _server.Shutdown(SocketShutdown.Both);
                _server.Close();
            }
            catch (ArgumentNullException ane)
            {
                Console.WriteLine("ArgumentNullException : {0}", ane.ToString());
            }
            catch (SocketException se)
            {
                Console.WriteLine("SocketException : {0}", se.ToString());
            }
            catch (Exception e)
            {
                Console.WriteLine("Unexpected exception : {0}", e.ToString());
            }
        }

        public static void RecieveServerResponse()
        {
            List<byte> totalMessage = new List<byte>();
            byte[] buf = new byte[256];
            int size = _server.Receive(buf);
            string code = Encoding.ASCII.GetString(buf[0..5]);
            int totalSize = BitConverter.ToInt32(buf[5..9]);
            int currentTotal = size;
            totalMessage.AddRange(buf[9..size]);
            while (currentTotal < totalSize + 5)
            {
                size = _server.Receive(buf);
                totalMessage.AddRange(buf);
                currentTotal += size;
            }

            var totalResponse = totalMessage.ToArray();

            switch (code)
            {
                case "<KEY>":
                    ECDiffieHellmanOpenSsl peerKey = new ECDiffieHellmanOpenSsl(ECCurve.NamedCurves.nistP521);
                    peerKey.ImportSubjectPublicKeyInfo(totalResponse, out _);
                    sessionKey = ecdhKey.DeriveKeyMaterial(peerKey.PublicKey);

                    break;
                case "<TXT>":
                    string decryptedMessage = CryptoHelp.GetDecryptedMessage(sessionKey, totalResponse);
                    Console.WriteLine(decryptedMessage);
                    File.WriteAllText("tmp.txt", decryptedMessage);
                    break;
                case "<DIR>":
                    string container = Encoding.ASCII.GetString(totalResponse);
                    Console.WriteLine(container);
                    break;
                case "<SUC>":
                    break;
                case "<ERR>":
                    break;
                default:
                    break;
            }
        }

        public static void GenerateNewEcdh()
        {
            ECCurve kurwa = ECCurve.NamedCurves.nistP521;
            ECDiffieHellman daKey = ECDiffieHellman.Create(kurwa);
            SaveEcdsa(daKey);
        }

        public static void SaveEcdsa(ECDiffieHellman key)
        {
            ECParameters parameters = key.ExportParameters(true);
            List<byte> persist = new List<byte>();
            byte[] dParam = parameters.D;
            byte[] xParam = parameters.Q.X;
            byte[] yParam = parameters.Q.Y;
            persist.AddRange(BitConverter.GetBytes(dParam.Length));
            persist.AddRange(dParam);
            persist.AddRange(BitConverter.GetBytes(xParam.Length));
            persist.AddRange(xParam);
            persist.AddRange(BitConverter.GetBytes(yParam.Length));
            persist.AddRange(yParam);
            File.WriteAllBytes("keys.k", persist.ToArray());
        }

        public static ECDiffieHellman LoadEcdh()
        {
            ECParameters parameters = new ECParameters();
            byte[] buf = File.ReadAllBytes("keys.k");
            int offset = 0;
            int dSize = BitConverter.ToInt32(buf[offset..(offset + 4)]);
            offset += 4;
            byte[] dParam = buf[offset..(offset + dSize)];
            offset += dSize;
            int xSize = BitConverter.ToInt32(buf[offset..(offset + 4)]);
            offset += 4;
            byte[] xParam = buf[offset..(offset + xSize)];
            offset += xSize;
            int ySize = BitConverter.ToInt32(buf[offset..(offset + 4)]);
            offset += 4;
            byte[] yParam = buf[offset..(offset + ySize)];
            offset += ySize;

            parameters.Curve = ECCurve.NamedCurves.nistP521;
            parameters.D = dParam;
            parameters.Q = new ECPoint();
            parameters.Q.X = xParam;
            parameters.Q.Y = yParam;

            ECDiffieHellman eCDH = ECDiffieHellman.Create(parameters);
            return eCDH;
        }

        public static byte[] CreateInitialRequest(string login, string password)
        {
            List<byte> requestLine = new List<byte>();
            ecdhKey = LoadEcdh();
            byte[] loginBytes = Encoding.ASCII.GetBytes(login);
            byte[] passwordBytes = Encoding.ASCII.GetBytes(password);
            requestLine.AddRange(Encoding.ASCII.GetBytes("<SET>"));
            requestLine.AddRange(BitConverter.GetBytes(loginBytes.Length));
            requestLine.AddRange(loginBytes);
            requestLine.AddRange(BitConverter.GetBytes(passwordBytes.Length));
            requestLine.AddRange(passwordBytes);
            requestLine.AddRange(ecdhKey.ExportSubjectPublicKeyInfo());
            requestLine.AddRange(Encoding.ASCII.GetBytes("<EOF>"));
            return requestLine.ToArray();
        }

        public static byte[] CreateGetRequest(string pathToFile)
        {
            List<byte> requestLine = new List<byte>();
            requestLine.AddRange(Encoding.ASCII.GetBytes("<GET>"));
            requestLine.AddRange(BitConverter.GetBytes(pathToFile.Length));
            requestLine.AddRange(Encoding.ASCII.GetBytes(pathToFile));
            requestLine.AddRange(Encoding.ASCII.GetBytes("<EOF>"));
            return requestLine.ToArray();
        }

        public static byte[] CreateDirRequest()
        {
            List<byte> requestLine = new List<byte>();
            requestLine.AddRange(Encoding.ASCII.GetBytes("<DIR>"));
            requestLine.AddRange(Encoding.ASCII.GetBytes("<EOF>"));
            return requestLine.ToArray();
        }

        public static byte[] CreateNewRequest(string pathToFile, string message)
        {
            List<byte> requestLine = new List<byte>();
            byte[] file = Encoding.ASCII.GetBytes(pathToFile);
            requestLine.AddRange(Encoding.ASCII.GetBytes("<NEW>"));
            requestLine.AddRange(BitConverter.GetBytes(file.Length));
            requestLine.AddRange(file);
            byte[] encMsg = CryptoHelp.GetEncryptedMessage(sessionKey, message);
            requestLine.AddRange(encMsg);
            requestLine.AddRange(Encoding.ASCII.GetBytes("<EOF>"));
            return requestLine.ToArray();
        }

        public static byte[] CreateDelRequest(string pathToFile)
        {
            List<byte> requestLine = new List<byte>();
            byte[] file = Encoding.ASCII.GetBytes(pathToFile);
            requestLine.AddRange(Encoding.ASCII.GetBytes("<DEL>"));
            requestLine.AddRange(file);
            requestLine.AddRange(Encoding.ASCII.GetBytes("<EOF>"));
            return requestLine.ToArray();
        }
    }
}
