namespace HashCracker.Models;

public enum CrackStatus { Found, Exhausted, Cancelled }

public class CrackResult
{
    public CrackStatus Status { get; init; }
    public bool Found => Status == CrackStatus.Found;
    public string? Password { get; init; }
    public double ElapsedSeconds { get; init; }
    public long AttemptsCount { get; init; }
    public long TotalCombinations { get; init; }
    public int WorkerCount { get; init; }
    public string Alphabet { get; init; } = "";
}
