using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

class Program
{
    static void Main(string[] args)
    {
        string inputFilePath = "input.txt"; // Вхідний текстовий файл
        string outputFilePath = "encrypted.bin"; // Файл для збереження шифротексту

        // AES-GCM параметри
        byte[] key = GenerateRandomBytes(32); // 256-бітний ключ
        byte[] iv = GenerateRandomBytes(12); // 96-бітний IV

        // Читання тексту з файлу
        string plainText = File.ReadAllText(inputFilePath);

        // Шифрування
        (byte[] cipherText, byte[] authTag) = EncryptAesGcm(plainText, key, iv);

        // Запис у файл: IV, шифротекст і тег автентифікації
        using (FileStream fileStream = new FileStream(outputFilePath, FileMode.Create))
        {
            fileStream.Write(iv, 0, iv.Length);
            fileStream.Write(cipherText, 0, cipherText.Length);
            fileStream.Write(authTag, 0, authTag.Length);
        }

        Console.WriteLine($"Файл успішно зашифрований та збережений у {outputFilePath}");
    }

    static (byte[] cipherText, byte[] authTag) EncryptAesGcm(string plainText, byte[] key, byte[] iv)
    {
        using (AesGcm aesGcm = new AesGcm(key))
        {
            byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
            byte[] cipherText = new byte[plainBytes.Length];
            byte[] authTag = new byte[16]; // 128-бітний тег автентифікації

            aesGcm.Encrypt(iv, plainBytes, cipherText, authTag);

            return (cipherText, authTag);
        }
    }

    static byte[] GenerateRandomBytes(int length)
    {
        byte[] bytes = new byte[length];
        using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(bytes);
        }
        return bytes;
    }
}
