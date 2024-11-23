using System;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

class Program
{
    static void Main()
    {
        string keysDirectory = "keys";
        string compressedDirectory = "compressed";
        Directory.CreateDirectory(keysDirectory);
        Directory.CreateDirectory(compressedDirectory);

        while (true)
        {
            Console.WriteLine("\nMenú:");
            Console.WriteLine("1. Generar par de claves");
            Console.WriteLine("2. Listar llaves públicas y privadas");
            Console.WriteLine("3. Firmar mensaje");
            Console.WriteLine("4. Listar archivos comprimidos");
            Console.WriteLine("5. Verificar firma");
            Console.WriteLine("6. Verificar firma con otra clave pública");
            Console.WriteLine("7. Salir");
            Console.Write("Seleccione una opción: ");
            string option = Console.ReadLine();

            switch (option)
            {
                case "1":
                    GenerateKeyPair(keysDirectory);
                    break;
                case "2":
                    ListKeys(keysDirectory);
                    break;
                case "3":
                    SignMessage(keysDirectory, compressedDirectory);
                    break;
                case "4":
                    ListCompressedFiles(compressedDirectory);
                    break;
                case "5":
                    VerifySignature(compressedDirectory);
                    break;
                case "6":
                    VerifySignatureWithAnotherKey(keysDirectory, compressedDirectory);
                    break;
                case "7":
                    return;
                default:
                    Console.WriteLine("Opción inválida.");
                    Console.ReadKey();

                    break;
            }
        }
    }

    static void GenerateKeyPair(string keysDirectory)
    {
        using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
        {
            string timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
            string privateKeyPath = Path.Combine(keysDirectory, $"clave_privada_{timestamp}.xml");
            string publicKeyPath = Path.Combine(keysDirectory, $"clave_publica_{timestamp}.xml");

            File.WriteAllText(privateKeyPath, ToXmlString(rsa.ExportParameters(true)));
            File.WriteAllText(publicKeyPath, ToXmlString(rsa.ExportParameters(false)));

            Console.WriteLine($"Claves generadas:\nClave privada: {privateKeyPath}\nClave pública: {publicKeyPath}");
        }
    }

    static void ListKeys(string keysDirectory)
    {
        var files = Directory.GetFiles(keysDirectory);
        if (!files.Any())
        {
            Console.WriteLine("No hay claves generadas.");
            return;
        }

        Console.WriteLine("Claves generadas:");
        foreach (var file in files)
        {
            Console.WriteLine(Path.GetFileName(file));
        }
    }

    static void SignMessage(string keysDirectory, string compressedDirectory)
    {
        Console.Write("Ingrese el mensaje a firmar: ");
        string message = Console.ReadLine();
        byte[] messageBytes = Encoding.UTF8.GetBytes(message);

        Console.WriteLine("Claves privadas disponibles:");
        var privateKeyFiles = Directory.GetFiles(keysDirectory, "clave_privada_*.xml");
        if (!privateKeyFiles.Any())
        {
            Console.WriteLine("No hay claves privadas disponibles.");
            return;
        }

        for (int i = 0; i < privateKeyFiles.Length; i++)
        {
            Console.WriteLine($"{i + 1}. {Path.GetFileName(privateKeyFiles[i])}");
        }

        Console.Write("Seleccione una clave privada por su número: ");
        if (!int.TryParse(Console.ReadLine(), out int privateKeyIndex) || privateKeyIndex < 1 || privateKeyIndex > privateKeyFiles.Length)
        {
            Console.WriteLine("Selección inválida.");
            return;
        }

        string selectedPrivateKeyPath = privateKeyFiles[privateKeyIndex - 1];
        string correspondingPublicKeyPath = selectedPrivateKeyPath.Replace("clave_privada_", "clave_publica_");
        if (!File.Exists(correspondingPublicKeyPath))
        {
            Console.WriteLine("La clave pública correspondiente no se encontró.");
            return;
        }

        using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
        {
            // Leer la clave privada y generar la firma
            rsa.FromXmlString(File.ReadAllText(selectedPrivateKeyPath));
            byte[] signature = rsa.SignData(messageBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

            string timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
            string compressedFilePath = Path.Combine(compressedDirectory, $"firma_{timestamp}.zip");

            using (var archive = ZipFile.Open(compressedFilePath, ZipArchiveMode.Create))
            {
                // Agregar la clave pública correspondiente al archivo comprimido
                var publicKeyEntry = archive.CreateEntry("clave_publica.xml");
                using (var publicKeyStream = publicKeyEntry.Open())
                {
                    byte[] publicKeyBytes = File.ReadAllBytes(correspondingPublicKeyPath);
                    publicKeyStream.Write(publicKeyBytes, 0, publicKeyBytes.Length);
                }

                // Agregar el mensaje al archivo comprimido
                var messageEntry = archive.CreateEntry("mensaje.txt");
                using (var messageStream = messageEntry.Open())
                {
                    messageStream.Write(messageBytes, 0, messageBytes.Length);
                }

                // Agregar la firma al archivo comprimido
                var signatureEntry = archive.CreateEntry("firma.txt");
                using (var signatureStream = signatureEntry.Open())
                {
                    signatureStream.Write(signature, 0, signature.Length);
                }
            }

            Console.WriteLine($"Archivo comprimido generado: {compressedFilePath}");
        }

    }

    static void ListCompressedFiles(string compressedDirectory)
    {
        var files = Directory.GetFiles(compressedDirectory);
        if (!files.Any())
        {
            Console.WriteLine("No hay archivos comprimidos.");
            return;
        }

        Console.WriteLine("Archivos comprimidos:");
        foreach (var file in files)
        {
            Console.WriteLine(Path.GetFileName(file));
        }
    }

    static void VerifySignature(string compressedDirectory)
    {
        var compressedFiles = Directory.GetFiles(compressedDirectory, "*.zip");
        if (!compressedFiles.Any())
        {
            Console.WriteLine("No hay archivos comprimidos disponibles.");
            return;
        }

        Console.WriteLine("Archivos comprimidos disponibles:");
        for (int i = 0; i < compressedFiles.Length; i++)
        {
            Console.WriteLine($"{i + 1}. {Path.GetFileName(compressedFiles[i])}");
        }

        Console.Write("Seleccione un archivo por su número: ");
        if (!int.TryParse(Console.ReadLine(), out int fileIndex) || fileIndex < 1 || fileIndex > compressedFiles.Length)
        {
            Console.WriteLine("Selección inválida.");
            return;
        }

        string selectedCompressedFilePath = compressedFiles[fileIndex - 1];

        using (var archive = ZipFile.OpenRead(selectedCompressedFilePath))
        {
            var publicKeyEntry = archive.GetEntry("clave_publica.xml");
            var messageEntry = archive.GetEntry("mensaje.txt");
            var signatureEntry = archive.GetEntry("firma.txt");

            if (publicKeyEntry == null || messageEntry == null || signatureEntry == null)
            {
                Console.WriteLine("El archivo comprimido no contiene todos los elementos necesarios.");
                return;
            }

            using (var publicKeyStream = publicKeyEntry.Open())
            using (var messageStream = messageEntry.Open())
            using (var signatureStream = signatureEntry.Open())
            {
                string publicKey = new StreamReader(publicKeyStream).ReadToEnd();
                byte[] messageBytes = new BinaryReader(messageStream).ReadBytes((int)messageEntry.Length);
                byte[] signatureBytes = new BinaryReader(signatureStream).ReadBytes((int)signatureEntry.Length);

                using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
                {
                    rsa.FromXmlString(publicKey);
                    bool isValid = rsa.VerifyData(messageBytes, signatureBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

                    Console.WriteLine(isValid ? "La firma es válida." : "La firma es inválida.");
                }
            }
        }
    }

    static void VerifySignatureWithAnotherKey(string keysDirectory, string compressedDirectory)
    {
        var compressedFiles = Directory.GetFiles(compressedDirectory, "*.zip");
        if (!compressedFiles.Any())
        {
            Console.WriteLine("No hay archivos comprimidos disponibles.");
            return;
        }

        Console.WriteLine("Archivos comprimidos disponibles:");
        for (int i = 0; i < compressedFiles.Length; i++)
        {
            Console.WriteLine($"{i + 1}. {Path.GetFileName(compressedFiles[i])}");
        }

        Console.Write("Seleccione un archivo por su número: ");
        if (!int.TryParse(Console.ReadLine(), out int fileIndex) || fileIndex < 1 || fileIndex > compressedFiles.Length)
        {
            Console.WriteLine("Selección inválida.");
            return;
        }

        string selectedCompressedFilePath = compressedFiles[fileIndex - 1];

        var publicKeyFiles = Directory.GetFiles(keysDirectory, "clave_publica_*.xml");
        if (!publicKeyFiles.Any())
        {
            Console.WriteLine("No hay claves públicas disponibles.");
            return;
        }

        Console.WriteLine("Claves públicas disponibles:");
        for (int i = 0; i < publicKeyFiles.Length; i++)
        {
            Console.WriteLine($"{i + 1}. {Path.GetFileName(publicKeyFiles[i])}");
        }

        Console.Write("Seleccione una clave pública por su número: ");
        if (!int.TryParse(Console.ReadLine(), out int publicKeyIndex) || publicKeyIndex < 1 || publicKeyIndex > publicKeyFiles.Length)
        {
            Console.WriteLine("Selección inválida.");
            return;
        }

        string selectedPublicKeyPath = publicKeyFiles[publicKeyIndex - 1];

        using (var archive = ZipFile.OpenRead(selectedCompressedFilePath))
        {
            var publicKeyEntry = archive.GetEntry("clave_publica.xml");
            var messageEntry = archive.GetEntry("mensaje.txt");
            var signatureEntry = archive.GetEntry("firma.txt");

            if (publicKeyEntry == null || messageEntry == null || signatureEntry == null)
            {
                Console.WriteLine("El archivo comprimido no contiene todos los elementos necesarios.");
                return;
            }

            using (var selectedPublicKeyStream = new FileStream(selectedPublicKeyPath, FileMode.Open, FileAccess.Read))
            using (var messageStream = messageEntry.Open())
            using (var signatureStream = signatureEntry.Open())
            {
                string publicKey = new StreamReader(selectedPublicKeyStream).ReadToEnd();
                byte[] messageBytes = new BinaryReader(messageStream).ReadBytes((int)messageEntry.Length);
                byte[] signatureBytes = new BinaryReader(signatureStream).ReadBytes((int)signatureEntry.Length);

                using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
                {
                    rsa.FromXmlString(publicKey);
                    bool isValid = rsa.VerifyData(messageBytes, signatureBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

                    Console.WriteLine(isValid ? "La firma es válida con la clave seleccionada." : "La firma es inválida con la clave seleccionada.");
                }
            }
        }
    }

    static string ToXmlString(RSAParameters rsaParameters)
    {
        using (var sw = new StringWriter())
        {
            var xs = new System.Xml.Serialization.XmlSerializer(typeof(RSAParameters));
            xs.Serialize(sw, rsaParameters);
            return sw.ToString();
        }
    }
}