using System;
using System.IO;
using PeNet; // Для роботи з PE-файлами
using ELFSharp.ELF; // Для роботи з ELF-файлами
using ELFSharp.ELF.Sections;

class Program
{
    static void Main(string[] args)
    {
        if (args.Length != 1)
        {
            Console.WriteLine("Usage: analyze <file_path>");
            return;
        }

        string filePath = args[0];

        try
        {
            byte[] magic = new byte[4];
            using (var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read))
            {
                stream.Read(magic, 0, 4);
            }

            if (magic[0] == 'M' && magic[1] == 'Z') // Перевірка на PE-файл
            {
                AnalyzePE(filePath);
            }
            else if (magic[0] == 0x7F && magic[1] == 'E' && magic[2] == 'L' && magic[3] == 'F') // Перевірка на ELF-файл
            {
                AnalyzeELF(filePath);
            }
            else
            {
                Console.WriteLine("Unsupported file format. Please provide a PE or ELF file.");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error: {ex.Message}");
        }
    }

    static void AnalyzePE(string filePath)
    {
        try
        {
            var peFile = new PeFile(filePath);
            Console.WriteLine($"Analyzing PE file: {filePath}");
            Console.WriteLine("Imported Libraries and Functions:");

            if (peFile.ImportedFunctions != null)
            {
                foreach (var func in peFile.ImportedFunctions)
                {
                    Console.WriteLine($"  Function: {func}");
                }
            }

            if (peFile.ImportedDlls != null)
            {
                foreach (var dll in peFile.ImportedDlls)
                {
                    Console.WriteLine($"Library: {dll}");
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error analyzing PE file: {ex.Message}");
        }
    }

    static void AnalyzeELF(string filePath)
    {
        try
        {
            var elf = ELFReader.Load(filePath);
            Console.WriteLine($"Analyzing ELF file: {filePath}");
            Console.WriteLine("Imported Libraries and Functions:");

            foreach (var section in elf.Sections)
            {
                if (section.Name == ".dynsym") // Динамічні символи
                {
                    var symbolTable = section as ISymbolTable;
                    foreach (var symbol in symbolTable.Entries)
                    {
                        Console.WriteLine($"  Function: {symbol.Name}");
                    }
                }
            }

            foreach (var lib in elf.GetNeededLibraries()) // Залежні бібліотеки
            {
                Console.WriteLine($"Library: {lib}");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error analyzing ELF file: {ex.Message}");
        }
    }
}
