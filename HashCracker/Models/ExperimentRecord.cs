using HashCracker.Services;

namespace HashCracker.Models;

public sealed record ExperimentRecord(DateTimeOffset StartedAt, HashAlgorithmType Algorithm,
    string TargetHash, int MinLength, int MaxLength, int RequestedThreads, CrackResult Result);
