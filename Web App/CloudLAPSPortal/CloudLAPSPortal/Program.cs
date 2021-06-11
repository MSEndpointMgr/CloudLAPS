using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Azure.Identity;

namespace CloudLAPSPortal
{
    public class Program
    {
        public static void Main(string[] args)
        {
            CreateHostBuilder(args).Build().Run();
        }

        public static IHostBuilder CreateHostBuilder(string[] args) =>
            Host.CreateDefaultBuilder(args)
                // This seems to be adding secrets to specified Key Vault if any secret matching what's defined in appsettings.json, e.g. SecretName
                // Is this really required? https://cmatskas.com/secure-app-development-with-azure-ad-key-vault-and-managed-identities/

                //.ConfigureAppConfiguration((context, config) =>
                //{
                //var builtConfig = config.Build();
                //config.AddAzureKeyVault(new Uri("https://cloudlapsvault.vault.azure.net"),
                //new DefaultAzureCredential());
                //})
                //' End
                .ConfigureWebHostDefaults(webBuilder =>
                {
                    webBuilder.UseStartup<Startup>();
                });
    }
}
