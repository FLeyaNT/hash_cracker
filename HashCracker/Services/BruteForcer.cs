using System.Diagnostics;
using System.Security.Cryptography;
using HashCracker.Models;
using Konscious.Security.Cryptography;

namespace HashCracker.Services;

public enum HashAlgorithmType { MD5, SHA1, BCrypt, Argon2 }

// Проверка параметров вынесена в BruteForcer.Validation.cs.
public partial class BruteForcer
{
    private int _running;
    private int _cancelRequested;
    private int _stopRequested;
    private int _nextFirstSymbol;
    private long _attempts;
    private string? _foundPassword;

    private bool ShouldStop =>
        Volatile.Read(ref _cancelRequested) != 0 || Volatile.Read(ref _stopRequested) != 0;

    public void Cancel() => Volatile.Write(ref _cancelRequested, 1);

    public async Task<CrackResult> RunAsync(HashAlgorithmType type, string targetHash, string alphabet,
        int minLen, int maxLen, int threadCount, Action<string> log)
    {
        if (Interlocked.CompareExchange(ref _running, 1, 0) != 0)
            throw new InvalidOperationException("Этот переборщик уже выполняет поиск.");

        try
        {
            ResetSearch();
            var search = Prepare(type, targetHash, alphabet, minLen, maxLen, threadCount);
            int workerCount = Math.Min(threadCount, search.Symbols.Length);
            int maxWorkersUsed = 0;
            var stopwatch = Stopwatch.StartNew();

            // Каждую длину полностью проверяем перед переходом к следующей.
            for (int length = minLen; length <= maxLen; length++)
            {
                if (ShouldStop) break;
                log($"Перебор паролей длины {length}...");
                maxWorkersUsed = workerCount;
                await SearchLengthAsync(search, length, workerCount);
            }

            stopwatch.Stop();
            return CreateResult(search, stopwatch.Elapsed.TotalSeconds, maxWorkersUsed);
        }
        finally
        {
            Volatile.Write(ref _running, 0);
        }
    }

    private void ResetSearch()
    {
        Volatile.Write(ref _cancelRequested, 0);
        Volatile.Write(ref _stopRequested, 0);
        Interlocked.Exchange(ref _attempts, 0);
        _foundPassword = null;
    }

    private async Task SearchLengthAsync(PreparedSearch search, int length, int workerCount)
    {
        // Общая очередь первых символов начинается заново для каждой длины.
        _nextFirstSymbol = -1;
        var tasks = new Task[workerCount];
        for (int worker = 0; worker < workerCount; worker++)
            tasks[worker] = Task.Run(() => SearchWorker(search, length));

        await Task.WhenAll(tasks);
    }

    private void SearchWorker(PreparedSearch search, int length)
    {
        long localAttempts = 0;
        try
        {
            using var hasher = CreateHasher(search.Algorithm);
            int[] positions = new int[length];
            byte[] passwordBytes = new byte[length * 4];
            byte[] hashBytes = new byte[20];

            while (!ShouldStop)
            {
                // Interlocked выдаёт каждой задаче свой следующий символ без повторов.
                int firstSymbol = Interlocked.Increment(ref _nextFirstSymbol);
                if (firstSymbol >= search.Symbols.Length) break;

                Array.Clear(positions);
                positions[0] = firstSymbol;
                do
                {
                    if (ShouldStop) return;

                    int byteCount = WritePasswordBytes(search, positions, passwordBytes);
                    bool matches = MatchesHash(search, hasher, passwordBytes.AsSpan(0, byteCount), hashBytes);
                    localAttempts++;

                    if (matches)
                    {
                        string password = Utf8.GetString(passwordBytes, 0, byteCount);
                        Interlocked.CompareExchange(ref _foundPassword, password, null);
                        Volatile.Write(ref _stopRequested, 1);
                        return;
                    }
                }
                while (MoveToNextSuffix(positions, search.Symbols.Length));
            }
        }
        catch
        {
            Volatile.Write(ref _stopRequested, 1);
            throw;
        }
        finally
        {
            Interlocked.Add(ref _attempts, localAttempts);
        }
    }

    // positions хранит индексы символов в алфавите, например [2, 0, 1] для "201".
    private static int WritePasswordBytes(PreparedSearch search, int[] positions, byte[] buffer)
    {
        int offset = 0;
        foreach (int position in positions)
        {
            byte[] symbolBytes = search.EncodedSymbols[position];
            symbolBytes.CopyTo(buffer, offset);
            offset += symbolBytes.Length;
        }
        return offset;
    }

    private static bool MoveToNextSuffix(int[] positions, int alphabetSize)
    {
        // Как счётчик: 00 → 01 → ... → 09 → 10. Первую позицию не меняем.
        for (int position = positions.Length - 1; position >= 1; position--)
        {
            positions[position]++;
            if (positions[position] < alphabetSize) return true;
            positions[position] = 0;
        }
        return false;
    }

    private static HashAlgorithm? CreateHasher(HashAlgorithmType type) => type switch
    {
        HashAlgorithmType.MD5 => MD5.Create(),
        HashAlgorithmType.SHA1 => SHA1.Create(),
        _ => null
    };

    private static bool MatchesHash(PreparedSearch search, HashAlgorithm? hasher,
        ReadOnlySpan<byte> passwordBytes, Span<byte> hashBuffer)
    {
        if (hasher is not null)
        {
            if (!hasher.TryComputeHash(passwordBytes, hashBuffer, out int bytesWritten))
                throw new CryptographicException("Не удалось вычислить хэш.");
            return hashBuffer[..bytesWritten].SequenceEqual(search.TargetBytes);
        }

        if (search.Algorithm == HashAlgorithmType.BCrypt)
            return BCrypt.Net.BCrypt.Verify(Utf8.GetString(passwordBytes), search.TargetHash);

        return VerifyArgon2(passwordBytes, search.Argon2!);
    }

    private static bool VerifyArgon2(ReadOnlySpan<byte> candidate, Argon2Params parameters)
    {
        using var argon = new Argon2id(candidate.ToArray())
        {
            Salt = parameters.Salt,
            DegreeOfParallelism = parameters.Parallelism,
            MemorySize = parameters.MemoryKb,
            Iterations = parameters.Iterations
        };
        return CryptographicOperations.FixedTimeEquals(
            argon.GetBytes(parameters.ExpectedHash.Length), parameters.ExpectedHash);
    }

    private CrackResult CreateResult(PreparedSearch search, double elapsedSeconds, int workersUsed)
    {
        CrackStatus status = CrackStatus.Exhausted;
        if (_foundPassword is not null)
            status = CrackStatus.Found;
        else if (Volatile.Read(ref _cancelRequested) != 0 && _attempts < search.Total)
            status = CrackStatus.Cancelled;

        return new CrackResult
        {
            Status = status,
            Password = _foundPassword,
            ElapsedSeconds = elapsedSeconds,
            AttemptsCount = _attempts,
            TotalCombinations = search.Total,
            WorkerCount = workersUsed,
            Alphabet = search.Alphabet
        };
    }

}
