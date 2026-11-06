using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using HashCracker.Models;
using HashCracker.Services;
using Konscious.Security.Cryptography;
using Microsoft.VisualBasic.FileIO;

int passed = 0;
int threads = Math.Min(4, Environment.ProcessorCount);
string Md5(string text) => Convert.ToHexString(MD5.HashData(Encoding.UTF8.GetBytes(text)));
string Sha1(string text) => Convert.ToHexString(SHA1.HashData(Encoding.UTF8.GetBytes(text)));
void Check(bool condition, string message)
{
    if (!condition) throw new Exception(message);
}
async Task Test(string name, Func<Task> body)
{
    await body();
    passed++;
    Console.WriteLine($"PASS {name}");
}
void Reject(HashAlgorithmType type, string hash, string alphabet = "ab", int min = 1, int max = 2, int? workers = null)
{
    try { BruteForcer.ValidateParameters(type, hash, alphabet, min, max, workers ?? threads); }
    catch (ArgumentException) { return; }
    throw new Exception($"Accepted invalid input: {type}, {hash}, {min}..{max}");
}
Task<CrackResult> Search(HashAlgorithmType type, string hash, string alphabet, int min, int max) =>
    new BruteForcer().RunAsync(type, hash, alphabet, min, max, threads, _ => { });

await Test("Exhaustive search covers every short password", async () =>
{
    var words = new List<string> { "" };
    for (int length = 1; length <= 3; length++)
    {
        words = words.SelectMany(prefix => "abc".Select(c => prefix + c)).ToList();
        foreach (string password in words)
        {
            var r = await Search(HashAlgorithmType.MD5, Md5(password), "abc", 1, 3);
            Check(r.Status == CrackStatus.Found && r.Password == password, $"Missed {password}");
            Check(r.AttemptsCount >= 1 && r.AttemptsCount <= 39 && r.TotalCombinations == 39, "Invalid attempt count");
        }
    }
});

await Test("Exhaustion counts each combination once across uneven ranges", async () =>
{
    foreach (int count in Enumerable.Range(1, threads))
    {
        var r = await new BruteForcer().RunAsync(HashAlgorithmType.MD5, Md5("outside"), "0123456789", 1, 3, count, _ => { });
        Check(r.Status == CrackStatus.Exhausted && r.AttemptsCount == 1110 && r.TotalCombinations == 1110, "Duplicate or missing work");
    }
});

await Test("First-symbol queue limits workers and covers all suffixes", async () =>
{
    var r = await Search(HashAlgorithmType.SHA1, Sha1("outside"), "ab", 4, 4);
    Check(r.AttemptsCount == 16 && r.WorkerCount == Math.Min(threads, 2), "Wrong task count or search space");
    var singleSymbol = await Search(HashAlgorithmType.MD5, Md5("outside"), "a", 4, 4);
    Check(singleSymbol.AttemptsCount == 1 && singleSymbol.WorkerCount == 1, "Single prefix must be processed exactly once");
});

await Test("One worker advances through first symbols in alphabet order", async () =>
{
    foreach (var (password, attempts) in new[] { ("09", 10), ("10", 11), ("29", 30), ("90", 91), ("99", 100) })
    {
        var r = await new BruteForcer().RunAsync(HashAlgorithmType.MD5, Md5(password), "0123456789", 2, 2, 1, _ => { });
        Check(r.Password == password && r.AttemptsCount == attempts, $"Wrong prefix/suffix order for {password}");
    }
});

await Test("MD5 and SHA1 use UTF-8 for Cyrillic and emoji", async () =>
{
    foreach (string password in new[] { "яя", "😀я", "я😀" })
    {
        var md5 = await Search(HashAlgorithmType.MD5, Md5(password).ToLowerInvariant(), "я😀", 2, 2);
        var sha1 = await Search(HashAlgorithmType.SHA1, Sha1(password), "я😀", 2, 2);
        Check(md5.Password == password && sha1.Password == password, "UTF-8 mismatch");
        Check(md5.TotalCombinations == 4, "Emoji counted as two symbols");
    }
});

await Test("Duplicate alphabet symbols are removed in original order", async () =>
{
    var r = await Search(HashAlgorithmType.MD5, Md5("outside"), "aababa😀😀", 1, 2);
    Check(r.Alphabet == "ab😀" && r.AttemptsCount == 12 && r.TotalCombinations == 12, "Duplicate symbols retained");
    Check(BruteForcer.NormalizeAlphabet("  a a") == " a", "Spaces must remain usable password symbols");
});

await Test("Hash and search-range validation", () =>
{
    Reject(HashAlgorithmType.MD5, "");
    Reject(HashAlgorithmType.MD5, "   ");
    Reject(HashAlgorithmType.MD5, "00");
    Reject(HashAlgorithmType.MD5, new string('g', 32));
    Reject(HashAlgorithmType.SHA1, new string('0', 39));
    Reject(HashAlgorithmType.SHA1, new string('0', 41));
    Reject(HashAlgorithmType.MD5, Md5("a"), "");
    Reject(HashAlgorithmType.MD5, Md5("a"), "\ud800");
    Reject(HashAlgorithmType.MD5, Md5("a"), min: -1);
    Reject(HashAlgorithmType.MD5, Md5("a"), min: 0);
    Reject(HashAlgorithmType.MD5, Md5("a"), min: 3, max: 2);
    Reject(HashAlgorithmType.MD5, Md5("a"), max: 129);
    Reject(HashAlgorithmType.MD5, Md5("a"), workers: 0);
    Reject(HashAlgorithmType.MD5, Md5("a"), workers: Environment.ProcessorCount + 1);
    Reject(HashAlgorithmType.MD5, Md5("a"), "ab", 63, 63);
    Reject((HashAlgorithmType)999, Md5("a"));
    return Task.CompletedTask;
});

await Test("Large allowed counts are exact and maximum length has no recursion", async () =>
{
    var forcer = new BruteForcer();
    var r = await forcer.RunAsync(HashAlgorithmType.MD5, Md5("outside"), "ab", 1, 62, threads, _ => forcer.Cancel());
    Check(r.Status == CrackStatus.Cancelled && r.TotalCombinations == 9223372036854775806L && r.AttemptsCount == 0, "Counter overflow");
    var maximumLength = await Search(HashAlgorithmType.MD5, Md5("outside"), "a", 1, 128);
    Check(maximumLength.Status == CrackStatus.Exhausted && maximumLength.AttemptsCount == 128, "Maximum-length search failed");
});

string bcrypt = BCrypt.Net.BCrypt.HashPassword("яb", 4);
await Test("bcrypt variants, UTF-8 and complete exhaustion", async () =>
{
    foreach (string revision in new[] { "2a", "2b", "2y" })
    {
        string hash = "$" + revision + bcrypt[3..];
        var r = await Search(HashAlgorithmType.BCrypt, hash, "яb", 2, 2);
        Check(r.Status == CrackStatus.Found && r.Password == "яb", $"bcrypt {revision} failed");
    }
    var exhausted = await Search(HashAlgorithmType.BCrypt, bcrypt, "ab", 1, 1);
    Check(exhausted.Status == CrackStatus.Exhausted && exhausted.AttemptsCount == 2, "bcrypt exhaustion failed");
});

await Test("bcrypt validates structure, cost and byte length before search", () =>
{
    Reject(HashAlgorithmType.BCrypt, "invalid");
    Reject(HashAlgorithmType.BCrypt, bcrypt[..^1]);
    Reject(HashAlgorithmType.BCrypt, bcrypt[..^1] + "!");
    Reject(HashAlgorithmType.BCrypt, bcrypt.Replace("$04$", "$03$"));
    Reject(HashAlgorithmType.BCrypt, bcrypt.Replace("$04$", "$17$"));
    Reject(HashAlgorithmType.BCrypt, bcrypt, "a", 73, 73);
    Reject(HashAlgorithmType.BCrypt, bcrypt, "😀", 19, 19);
    return Task.CompletedTask;
});

string MakeArgon(string password, int memory = 1024, int iterations = 1, int parallelism = 2)
{
    byte[] salt = Encoding.UTF8.GetBytes("saltsalt");
    using var argon = new Argon2id(Encoding.UTF8.GetBytes(password))
    { Salt = salt, MemorySize = memory, Iterations = iterations, DegreeOfParallelism = parallelism };
    return $"$argon2id$v=19$m={memory},t={iterations},p={parallelism}${Convert.ToBase64String(salt).TrimEnd('=')}${Convert.ToBase64String(argon.GetBytes(32)).TrimEnd('=')}";
}
string argonHash = MakeArgon("😀b");
await Test("Argon2id verifies UTF-8, shuffled parameters and padded Base64", async () =>
{
    var r = await Search(HashAlgorithmType.Argon2, argonHash.Replace("m=1024,t=1,p=2", "p=2,m=1024,t=1"), "😀b", 2, 2);
    Check(r.Password == "😀b", "Argon2id mismatch");
    string[] parts = argonHash.Split('$');
    parts[4] += "=";
    parts[5] += "=";
    var padded = await Search(HashAlgorithmType.Argon2, string.Join('$', parts), "😀b", 2, 2);
    Check(padded.Password == "😀b", "Padded Base64 rejected");
});

await Test("Argon2 rejects unsupported variants and malformed or excessive parameters", () =>
{
    foreach (string bad in new[]
    {
        argonHash.Replace("argon2id", "argon2i"), argonHash.Replace("argon2id", "argon2d"),
        argonHash.Replace("v=19", "v=16"), argonHash.Replace("m=1024,t=1,p=2", "m=1024,t=1"),
        argonHash.Replace("m=1024", "m=1024,m=1024"), argonHash.Replace("m=1024", "x=1024"),
        argonHash.Replace("m=1024", "m=-1"), argonHash.Replace("m=1024", "m=9999999999999999999"),
        argonHash.Replace("m=1024", "m=262145"), argonHash.Replace("m=1024", "m=8"),
        argonHash.Replace("t=1", "t=0"), argonHash.Replace("t=1", "t=101"),
        argonHash.Replace("p=2", "p=17"), argonHash + "$extra",
        argonHash.Replace("c2FsdHNhbHQ", "!"), argonHash.Replace("c2FsdHNhbHQ", "YQ"),
        argonHash.Replace("c2FsdHNhbHQ", "c2FsdHNhbHR")
    }) Reject(HashAlgorithmType.Argon2, bad);
    return Task.CompletedTask;
});

await Test("Homework hashes are accepted without starting a long search", () =>
{
    BruteForcer.ValidateParameters(HashAlgorithmType.BCrypt, "$2a$10$z4u9ZkvopUiiytaNX7wfGedy9Lu2ywUxwYpbsAR5YBrAuUs3YGXdi", "0123456789", 1, 6, threads);
    BruteForcer.ValidateParameters(HashAlgorithmType.Argon2, "$argon2id$v=19$m=65536,t=3,p=2$c2FsdHNhbHQ$PUF5UxxoUY++mMekkQwFurL0ZsTtB7lelO23zcyZQ0c", "0123456789", 1, 6, threads);
    return Task.CompletedTask;
});

await Test("Argon2 keeps the requested worker count regardless of aggregate memory", async () =>
{
    int requested = Environment.ProcessorCount;
    var forcer = new BruteForcer();
    string hash = "$argon2id$v=19$m=65536,t=3,p=2$c2FsdHNhbHQ$PUF5UxxoUY++mMekkQwFurL0ZsTtB7lelO23zcyZQ0c";
    // Cancel before hashing: test the worker selection without allocating memory for expensive checks.
    var result = await forcer.RunAsync(HashAlgorithmType.Argon2, hash, "0123456789", 6, 6,
        requested, _ => forcer.Cancel());
    Check(result.WorkerCount == Math.Min(requested, 10), "Argon2 silently reduced worker count");
    Check(result.Status == CrackStatus.Cancelled && result.AttemptsCount == 0, "Unexpected work after cancellation");
});

await Test("Cancellation interrupts active searches for every algorithm", async () =>
{
    foreach (var (type, hash, max) in new[]
    {
        (HashAlgorithmType.MD5, Md5("outside"), 40),
        (HashAlgorithmType.SHA1, Sha1("outside"), 40),
        (HashAlgorithmType.BCrypt, bcrypt, 20),
        (HashAlgorithmType.Argon2, argonHash, 20)
    })
    {
        var forcer = new BruteForcer();
        var running = forcer.RunAsync(type, hash, "ab", max, max, threads, _ => { });
        await Task.Delay(30);
        var stopWatch = Stopwatch.StartNew();
        forcer.Cancel();
        var r = await running.WaitAsync(TimeSpan.FromSeconds(5));
        Check(r.Status == CrackStatus.Cancelled && !r.Found && r.AttemptsCount < r.TotalCombinations, $"Wrong cancellation result for {type}");
        Console.WriteLine($"  {type}: stopped in {stopWatch.ElapsedMilliseconds} ms, attempts={r.AttemptsCount}");
    }
});

await Test("A found result is distinct from cancellation, and instances can be reused", async () =>
{
    var forcer = new BruteForcer();
    var first = await forcer.RunAsync(HashAlgorithmType.MD5, Md5("outside"), "ab", 10, 10, threads, _ => forcer.Cancel());
    Check(first.Status == CrackStatus.Cancelled, "Expected cancelled run");
    var second = await forcer.RunAsync(HashAlgorithmType.MD5, Md5("ab"), "ab", 2, 2, threads, _ => { });
    Check(second.Status == CrackStatus.Found && second.Found && second.Password == "ab", "Cancellation leaked to next run");
});

await Test("Concurrent runs on the same instance are rejected", async () =>
{
    var forcer = new BruteForcer();
    var first = forcer.RunAsync(HashAlgorithmType.MD5, Md5("outside"), "ab", 40, 40, threads, _ => { });
    try
    {
        try
        {
            await forcer.RunAsync(HashAlgorithmType.MD5, Md5("a"), "ab", 1, 1, threads, _ => { });
            throw new Exception("Concurrent run was accepted");
        }
        catch (InvalidOperationException) { }
    }
    finally { forcer.Cancel(); await first.WaitAsync(TimeSpan.FromSeconds(5)); }
});

await Test("CSV preserves parameters, Unicode, quotes, delimiters, newlines and append history", async () =>
{
    string directory = Path.Combine(Path.GetTempPath(), "HashCracker-tests-" + Guid.NewGuid().ToString("N"));
    Directory.CreateDirectory(directory);
    try
    {
        string history = Path.Combine(directory, "history.csv"), export = Path.Combine(directory, "export.csv");
        var record = new ExperimentRecord(DateTimeOffset.Parse("2026-11-05T18:30:00+03:00"), HashAlgorithmType.MD5,
            Md5("я;\"\n"), 1, 3, threads, new CrackResult
            {
                Status = CrackStatus.Found, Alphabet = "я;\"\n", Password = "я;\"\n", AttemptsCount = 17,
                TotalCombinations = 84, WorkerCount = threads, ElapsedSeconds = 0.123456789
            });
        await CsvResultStore.AppendAsync(history, record);
        await CsvResultStore.AppendAsync(history, record);
        await CsvResultStore.SaveAsync(export, new[] { record, record });
        foreach (string path in new[] { history, export })
        {
            using var parser = new TextFieldParser(path, Encoding.UTF8) { HasFieldsEnclosedInQuotes = true, TrimWhiteSpace = false };
            parser.SetDelimiters(";");
            Check(parser.ReadFields()!.Length == 13, "Wrong CSV header");
            for (int row = 0; row < 2; row++)
            {
                string[] fields = parser.ReadFields()!;
                Check(fields.Length == 13 && fields[3] == record.Result.Alphabet && fields[12] == record.Result.Password, "CSV roundtrip failed");
                Check(fields[8] == "Found" && fields[9] == "0.123456789" && fields[10] == "17", "CSV values changed");
            }
            Check(parser.EndOfData, "Duplicate headers or extra rows");
        }
    }
    finally
    {
        string resolved = Path.GetFullPath(directory);
        string tempRoot = Path.GetFullPath(Path.GetTempPath());
        if (Path.GetDirectoryName(resolved) == tempRoot.TrimEnd(Path.DirectorySeparatorChar) &&
            Path.GetFileName(resolved).StartsWith("HashCracker-tests-", StringComparison.Ordinal))
            Directory.Delete(resolved, true);
    }
});

Console.WriteLine($"All {passed} test groups passed.");
