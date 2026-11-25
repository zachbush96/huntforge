using System.Text.Json;
using Kusto.Language;
using Kusto.Language.Symbols;

var requests = JsonSerializer.Deserialize<Request[]>(Console.In.ReadToEnd(), new JsonSerializerOptions
{
    PropertyNameCaseInsensitive = true
}) ?? throw new InvalidDataException("Expected a validation batch.");

var results = requests.Select(request =>
{
    var columns = request.Columns.Select(column =>
        new ColumnSymbol(column.Key, ScalarTypes.GetSymbol(column.Value)
            ?? throw new InvalidDataException($"Unsupported column type: {column.Value}"))).ToArray();
    var globals = GlobalState.Default.WithDatabase(new DatabaseSymbol("HuntForge", new TableSymbol(request.Table, columns)));
    var parsed = KustoCode.Parse(request.Query);
    var checkedQuery = KustoCode.ParseAndAnalyze(request.Query, globals);
    var syntax = parsed.GetSyntaxDiagnostics().Where(x => x.Severity == "Error").Select(x => x.Message).ToArray();
    var errors = checkedQuery.GetDiagnostics().Where(x => x.Severity == "Error").Select(x => x.Message).ToArray();
    return new { syntax, errors, tabular = checkedQuery.ResultType is TableSymbol };
});
Console.WriteLine(JsonSerializer.Serialize(results));

record Request(string Table, Dictionary<string, string> Columns, string Query);
