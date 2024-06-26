// Cifrado Simétrico (Metodo: Advanced Encryption Standard)

using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

public class Simetrico
{
    public static (byte[], byte[]) ClaveAESyIV()
    {
        using (Aes aes = Aes.Create())
        {
            aes.GenerateKey();
            aes.GenerateIV();
            return (aes.Key, aes.IV);
        }
    }
    
    // Encrypt
    public static byte[] Encrypt(string mensaje, byte[] clave, byte[] iv)
    {
        using (Aes aes = Aes.Create())
        {
            aes.Key = clave;
            aes.IV = iv;
            ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
            using (MemoryStream ms = new MemoryStream())
            {
                using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                {
                    using (StreamWriter sw = new StreamWriter(cs))
                    {
                        sw.Write(mensaje);
                    }
                }
                return ms.ToArray();
            }
        }
    }

    // Decrypt 
    public static string Decrypt(byte[] cifrado, byte[] clave, byte[] iv)
    {
        using (Aes aes = Aes.Create())
        {
            aes.Key = clave;
            aes.IV = iv;
            ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
            using (MemoryStream ms = new MemoryStream(cifrado))
            {
                using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                {
                    using (StreamReader sr = new StreamReader(cs))
                    {
                        return sr.ReadToEnd();
                    }
                }
            }
        }
    }

    public static void Main()
    {
        var (clave, iv) = ClaveAESyIV();
        string mensaje = "Actividad 5 de la clase de criptografia";
        
        byte[] encrypted = Encrypt(mensaje, clave, iv);
        string decrypted = Decrypt(encrypted, clave, iv);
        
        // Se convierte a Base64 para poder ser leido por el usuario
        string encryptedBase64 = Convert.ToBase64String(encrypted);

        Console.WriteLine($"Mensaje Encrypted (Base64):\n\n{encryptedBase64}");
        Console.WriteLine($"\nMensaje Decrypted:\n{decrypted}");
    }
}
