using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;

namespace HashCracker.Services;

public partial class BruteForcer
{
    public const int MaxPasswordLength = 128;
    public const int MaxAlphabetSymbols = 1024;
    public const int MaxBcryptWorkFactor = 16;
    public const int MaxArgonMemoryKb = 262144;
    public const int MaxArgonIterations = 100;
    public const int MaxArgonParallelism = 16;
    private static readonly UTF8Encoding Utf8 = new(false, true);

    private sealed record Argon2Params(byte[] Salt, byte[] ExpectedHash, int MemoryKb, int Iterations, int Parallelism);
    private sealed record PreparedSearch(string Alphabet, string[] Symbols, byte[][] EncodedSymbols,
        long Total, byte[]? TargetBytes, Argon2Params? Argon2, HashAlgorithmType Algorithm, string TargetHash);

    public static string NormalizeAlphabet(string alphabet)
    {
        if (string.IsNullOrEmpty(alphabet)) throw new ArgumentException("Введите хотя бы один символ алфавита.");
        try { _ = Utf8.GetByteCount(alphabet); }
        catch (EncoderFallbackException) { throw new ArgumentException("Алфавит содержит повреждённый символ Unicode."); }

        var symbols = alphabet.Distinct().ToArray();
        if (symbols.Length > MaxAlphabetSymbols)
            throw new ArgumentException($"Допускается до {MaxAlphabetSymbols} уникальных символов алфавита.");
        return string.Concat(symbols.Select(r => r.ToString()));
    }

    public static void ValidateParameters(HashAlgorithmType type, string targetHash, string alphabet,
        int minLen, int maxLen, int threadCount) =>
        _ = Prepare(type, targetHash, alphabet, minLen, maxLen, threadCount);

    private static PreparedSearch Prepare(HashAlgorithmType type, string targetHash, string alphabet,
        int minLen, int maxLen, int threadCount)
    {
        if (string.IsNullOrWhiteSpace(targetHash)) throw new ArgumentException("Введите хэш для подбора пароля.");
        if (minLen < 1 || maxLen < minLen || maxLen > MaxPasswordLength)
            throw new ArgumentException($"Длины должны быть от 1 до {MaxPasswordLength}, минимальная не больше максимальной.");
        if (threadCount < 1 || threadCount > Environment.ProcessorCount)
            throw new ArgumentException("Выберите число потоков от 1 до количества доступных логических процессоров.");

        alphabet = NormalizeAlphabet(alphabet);
        string[] symbols = alphabet.Select(r => r.ToString()).ToArray();
        byte[][] encoded = symbols.Select(Utf8.GetBytes).ToArray();
        long total = CalculateTotalCombinations(symbols.Length, minLen, maxLen);
        byte[]? target = null;
        Argon2Params? argon = null;
        switch (type)
        {
            case HashAlgorithmType.MD5:
            case HashAlgorithmType.SHA1:
                int requiredLength = type == HashAlgorithmType.MD5 ? 32 : 40;
                if (targetHash.Length != requiredLength || !targetHash.All(char.IsAsciiHexDigit))
                    throw new ArgumentException($"Для {type} требуется ровно {requiredLength} шестнадцатеричных символов (0-9, a-f).");
                target = Convert.FromHexString(targetHash);
                break;
            case HashAlgorithmType.BCrypt:
                ValidateBcrypt(targetHash);
                if (maxLen * encoded.Max(s => s.Length) > 72)
                    throw new ArgumentException("Для bcrypt максимальная длина с учётом UTF-8 не должна превышать 72 байта. Уменьшите длину или измените алфавит.");
                break;
            case HashAlgorithmType.Argon2:
                argon = ParseArgon2Hash(targetHash);
                break;
            default:
                throw new ArgumentException("Выбран неподдерживаемый алгоритм.");
        }
        return new(alphabet, symbols, encoded, total, target, argon, type, targetHash);
    }

    private static long CalculateTotalCombinations(int alphabetSize, int minLen, int maxLen)
    {
        try
        {
            long total = 0, power = 1;
            checked
            {
                for (int len = 1; len <= maxLen; len++)
                {
                    power *= alphabetSize;
                    if (len >= minLen) total += power;
                }
            }
            return total;
        }
        catch (OverflowException)
        {
            throw new ArgumentException("Количество комбинаций превышает предел счётчика (9223372036854775807). Уменьшите алфавит или диапазон длин.");
        }
    }

    private static void ValidateBcrypt(string hash)
    {
        if (!Regex.IsMatch(hash, @"\A\$2[aby]\$(0[4-9]|[12][0-9]|3[01])\$[./A-Za-z0-9]{53}\z", RegexOptions.CultureInvariant))
            throw new ArgumentException("Ожидается bcrypt-хэш из 60 символов с префиксом $2a$, $2b$ или $2y$ и cost от 04 до 31.");
        if (int.Parse(hash.AsSpan(4, 2), CultureInfo.InvariantCulture) > MaxBcryptWorkFactor)
            throw new ArgumentException($"Для перебора в этой программе поддерживается bcrypt cost не выше {MaxBcryptWorkFactor}.");
        try { _ = BCrypt.Net.BCrypt.InterrogateHash(hash); }
        catch (BCrypt.Net.HashInformationException)
        {
            throw new ArgumentException("Строка bcrypt повреждена: проверьте соль и хэш.");
        }
    }

    private static Argon2Params ParseArgon2Hash(string hash)
    {
        if (hash.Length > 2048) throw new ArgumentException("Строка Argon2 слишком длинная.");
        string[] parts = hash.Split('$');
        if (parts.Length != 6 || parts[0] != "" || parts[1] != "argon2id" || parts[2] != "v=19")
            throw new ArgumentException("Поддерживается Argon2id версии 19: $argon2id$v=19$m=...,t=...,p=...$salt$hash.");

        var parameters = new Dictionary<string, int>(StringComparer.Ordinal);
        foreach (string parameter in parts[3].Split(','))
        {
            string[] pair = parameter.Split('=');
            if (pair.Length != 2 || pair[0] is not ("m" or "t" or "p") ||
                !int.TryParse(pair[1], NumberStyles.None, CultureInfo.InvariantCulture, out int value) || value < 1 ||
                !parameters.TryAdd(pair[0], value))
                throw new ArgumentException("Параметры Argon2 m, t и p должны быть положительными целыми числами без повторов.");
        }
        if (parameters.Count != 3) throw new ArgumentException("Для Argon2 требуются параметры m, t и p.");
        int memory = parameters["m"], iterations = parameters["t"], parallelism = parameters["p"];
        if (parallelism > MaxArgonParallelism || memory > MaxArgonMemoryKb || memory < 8L * parallelism || iterations > MaxArgonIterations)
            throw new ArgumentException($"Лимиты Argon2 в этой программе: p=1..{MaxArgonParallelism}, m=8*p..{MaxArgonMemoryKb} КиБ, t=1..{MaxArgonIterations}.");

        byte[] salt = DecodeBase64(parts[4]);
        byte[] expected = DecodeBase64(parts[5]);
        if (salt.Length is < 8 or > 1024 || expected.Length is < 4 or > 1024)
            throw new ArgumentException("Для Argon2 требуется соль длиной 8..1024 байта и хэш длиной 4..1024 байта.");
        return new(salt, expected, memory, iterations, parallelism);
    }

    private static byte[] DecodeBase64(string text)
    {
        if (text.Length == 0 || !Regex.IsMatch(text, @"\A[A-Za-z0-9+/]+={0,2}\z", RegexOptions.CultureInvariant))
            throw new ArgumentException("Соль или хэш Argon2 содержит недопустимые символы Base64.");
        try
        {
            string unpadded = text.TrimEnd('=');
            string padded = unpadded + new string('=', (4 - unpadded.Length % 4) % 4);
            if (text.Contains('=') && text != padded) throw new FormatException();
            byte[] decoded = Convert.FromBase64String(padded);
            if (Convert.ToBase64String(decoded).TrimEnd('=') != unpadded) throw new FormatException();
            return decoded;
        }
        catch (FormatException) { throw new ArgumentException("Соль или хэш Argon2 имеет некорректный формат Base64."); }
    }
}
