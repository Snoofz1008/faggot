using System;
using System.Collections.Generic;
using System.Net;
using System.Text;
using WebSocketSharp;
using WebSocketSharp.Server;
using WebSocketSharp.Net; // Required for HTTPS
using ExitGames.Client.Photon;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

public class GpBinaryV16Handler : WebSocketBehavior
{
    protected override void OnMessage(MessageEventArgs e)
    {
        if (e.IsBinary)
        {
            try
            {
                var decodedMessage = DecodeGpBinaryV16(e.RawData);
                Console.WriteLine("Decoded Photon Protocol 16 Message:");
                Console.WriteLine(decodedMessage);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error decoding Photon message: {ex.Message}");
            }
        }
        else
        {
            Console.WriteLine($"Received non-binary message: {e.Data}");
        }
    }

    private string DecodeGpBinaryV16(byte[] data)
    {
        StringBuilder output = new StringBuilder();
        try
        {
            Protocol16 protocol = new Protocol16();
            object result = protocol.Deserialize(new StreamBuffer(data));

            output.AppendLine("Decoded Content:");
            if (result is Dictionary<byte, object> parameters)
            {
                foreach (var key in parameters.Keys)
                {
                    output.AppendLine($"Key: {key}, Value: {parameters[key]}");
                }
            }
            else
            {
                output.AppendLine($"Decoded result: {result}");
            }
        }
        catch (Exception ex)
        {
            throw new Exception($"Failed to decode GpBinaryV16: {ex.Message}");
        }

        return output.ToString();
    }
}

public class Program
{
    private static X509Certificate2 LoadCertificateFromPem(string certPath, string keyPath)
    {
        var cert = File.ReadAllText(certPath);
        var key = File.ReadAllText(keyPath);

        // Parse the private key
        RsaPrivateCrtKeyParameters privateKey;
        using (var reader = new StringReader(key))
        {
            var pemObject = new PemReader(reader).ReadObject();
            if (pemObject is RsaPrivateCrtKeyParameters rsaKey)
            {
                privateKey = rsaKey;
            }
            else
            {
                throw new InvalidCastException("The private key is not in the expected RSA format.");
            }
        }

        // Parse the certificate
        var certBytes = File.ReadAllBytes(certPath);
        var certParser = new Org.BouncyCastle.X509.X509CertificateParser();
        var bouncyCastleCert = certParser.ReadCertificate(certBytes);

        // Convert private key to RSA
        var rsa = DotNetUtilities.ToRSA(privateKey);

        // Combine certificate and private key
        var x509Cert = new X509Certificate2(bouncyCastleCert.GetEncoded());
        return x509Cert.CopyWithPrivateKey(rsa);
    }

    public static void Main(string[] args)
    {
        var wssv = new WebSocketServer(IPAddress.Parse("127.0.0.1"), 3778, true);

        // Load the PEM files and create an X509Certificate2
        var cert = LoadCertificateFromPem("C:\\Users\\Owner\\certificate.pem", "C:\\Users\\Owner\\private-key.pem");
        wssv.SslConfiguration.ServerCertificate = cert;

        wssv.AddWebSocketService<GpBinaryV16Handler>("/decode");

        wssv.Start();
        Console.WriteLine("Secure WebSocket server started on wss://127.0.0.1:8080/");
        Console.WriteLine("Listening for GpBinaryV16 data...");

        Console.WriteLine("Press any key to stop the server.");
        Console.ReadKey();

        wssv.Stop();
    }
}
