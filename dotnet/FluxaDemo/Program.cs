// Entry-point dispatch: one project, two demo subcommands.
//   dotnet run --project FluxaDemo -- charge [merchant_order_id]
//   dotnet run --project FluxaDemo -- webhook
namespace FluxaDemo;

public static class Program
{
    public static async Task<int> Main(string[] args)
    {
        try
        {
            return (args.Length > 0 ? args[0] : "") switch
            {
                "charge" => await Charge.RunAsync(args[1..]),
                "webhook" => await Webhook.RunAsync(),
                _ => Usage(),
            };
        }
        // The process boundary: report why the fluxa call failed as one readable line rather
        // than dumping a screenful of stack trace.
        catch (Exception e) when (e is FluxaException or HttpRequestException)
        {
            Console.Error.WriteLine($"✗ {e.Message}");
            return 1;
        }
    }

    private static int Usage()
    {
        Console.Error.WriteLine("Usage:");
        Console.Error.WriteLine(
            "  dotnet run --project FluxaDemo -- charge [merchant_order_id]   create a charge and look it back up");
        Console.Error.WriteLine(
            "  dotnet run --project FluxaDemo -- webhook                      receive callbacks locally");
        return 2;
    }
}
