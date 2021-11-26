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
            Client._server.Send(Client.CreateInitialRequest("UserA", "11111"));
            Client.RecieveServerResponse();
            Client._server.Send(Client.CreateDirRequest());
            Client.RecieveServerResponse();
            Client._server.Send(Client.CreateGetRequest("file1.txt"));
            Client.RecieveServerResponse();
            Client._server.Send(Client.CreateNewRequest("file3.txt", "I HATE MYSELF AND I WANT TO DIE"));
            Client.RecieveServerResponse();

            Console.Read();
            Client.StopClient();
        }
    }
}
