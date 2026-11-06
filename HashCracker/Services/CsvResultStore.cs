using System.Globalization;
using System.IO;
using System.Text;
using HashCracker.Models;

namespace HashCracker.Services;

public static class CsvResultStore
{
    public static string DefaultPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "HashCracker", "results.csv");

    private const string Header = "StartedAt;Algorithm;TargetHash;Alphabet;MinLength;MaxLength;RequestedThreads;WorkersUsed;Status;ElapsedSeconds;Attempts;TotalCombinations;Password";

    public static async Task AppendAsync(string path, ExperimentRecord record)
    {
        string fullPath = Path.GetFullPath(path);
        Directory.CreateDirectory(Path.GetDirectoryName(fullPath)!);
        await using var stream = new FileStream(fullPath, FileMode.OpenOrCreate, FileAccess.Write, FileShare.Read, 4096, true);
        bool writeHeader = stream.Length == 0;
        stream.Seek(0, SeekOrigin.End);
        await using var writer = new StreamWriter(stream, new UTF8Encoding(true));
        if (writeHeader) await writer.WriteLineAsync(Header);
        await writer.WriteLineAsync(Format(record));
    }

    public static async Task SaveAsync(string path, IEnumerable<ExperimentRecord> records)
    {
        await using var writer = new StreamWriter(path, false, new UTF8Encoding(true));
        await writer.WriteLineAsync(Header);
        foreach (var record in records) await writer.WriteLineAsync(Format(record));
    }

    private static string Format(ExperimentRecord record)
    {
        var result = record.Result;
        string[] fields =
        [
            record.StartedAt.ToString("O", CultureInfo.InvariantCulture), record.Algorithm.ToString(),
            record.TargetHash, result.Alphabet, record.MinLength.ToString(CultureInfo.InvariantCulture),
            record.MaxLength.ToString(CultureInfo.InvariantCulture), record.RequestedThreads.ToString(CultureInfo.InvariantCulture),
            result.WorkerCount.ToString(CultureInfo.InvariantCulture), result.Status.ToString(),
            result.ElapsedSeconds.ToString("R", CultureInfo.InvariantCulture), result.AttemptsCount.ToString(CultureInfo.InvariantCulture),
            result.TotalCombinations.ToString(CultureInfo.InvariantCulture), result.Password ?? ""
        ];
        return string.Join(';', fields.Select(value => "\"" + value.Replace("\"", "\"\"") + "\""));
    }
}
