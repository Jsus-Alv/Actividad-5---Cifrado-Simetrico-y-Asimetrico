// Cifrado Asimétrico (Metodo: Rivest-Shamir-Adleman)

using System.Security.Cryptography;
using System.Text;

public class Asimetrico
{
    public static (string, string) ClavesRSA()
    {
        using (RSA rsa = RSA.Create())
        {
            // True = Clave Privada, False = Clave Pública
            return (rsa.ToXmlString(true), rsa.ToXmlString(false));
        }
    }

    // Encrypt
    public static byte[] Encrypt(string mensaje, string clavePublica)
    {
        using (RSA rsa = RSA.Create())
        {
            rsa.FromXmlString(clavePublica);
            return rsa.Encrypt(Encoding.UTF8.GetBytes(mensaje), RSAEncryptionPadding.OaepSHA256);
        }
    }

    // Decrypt
    public static string Decrypt(byte[] cifrado, string clavePrivada)
    {
        using (RSA rsa = RSA.Create())
        {
            rsa.FromXmlString(clavePrivada);
            return Encoding.UTF8.GetString(rsa.Decrypt(cifrado, RSAEncryptionPadding.OaepSHA256));
        }
    }

    public static void Main()
    {
        var (clavePrivada, clavePublica) = ClavesRSA();
        string mensaje = "Actividad 5 de la clase de criptografia";

        byte[] encrypted = Encrypt(mensaje, clavePublica);
        string decrypted = Decrypt(encrypted, clavePrivada);

        // Se convierte a Base64 para poder ser leido por el usuario
        string encryptedBase64 = Convert.ToBase64String(encrypted);

        Console.WriteLine($"Mensaje Encrypted (Base64): \n\n{encryptedBase64}");
        Console.WriteLine($"\nMensaje Decrypted: {decrypted}");
    }
}
