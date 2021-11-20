using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace Lab2Client
{
    class Program
    {
        static void Main(string[] args)
        {
            Client.StartClient();

            Client.GenerateNewEcdsa();
            Client._server.Send(Client.CreateInitialRequest());
            Client.RecieveServerResponse();
            Client._server.Send(Client.CreateDirRequest());
            Client.RecieveServerResponse();
            Client._server.Send(Client.CreateGetRequest("file1.txt"));
            Client.RecieveServerResponse();

            Console.Read();
            Client.StopClient();
        }
    }
}
