using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using CloudLAPSPortal.Models;
using Microsoft.Extensions.Configuration;

namespace CloudLAPSPortal.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> logger;
        private readonly IConfiguration configuration;

        public HomeController(ILogger<HomeController> _logger, IConfiguration _configuration)
        {
            logger = _logger;
            configuration = _configuration;
        }       

        public IActionResult Index()
        {
            return View();
        }

        public async Task<IActionResult> SearchAsync(string searchValue)
        {
            if (!string.IsNullOrEmpty(searchValue))
            {
                try
                {
                    // Construct new SecretClient with Key Vault uri from appsetting.json using managed system identity of web app
                    string keyVaultUri = configuration.GetSection("KeyVault")["Uri"];

                    KeyVaultSecret secret = await KeyVaultSecret.GetComputerAsync(keyVaultUri, searchValue);
                    if (secret != null)
                    {
                        // Construct new Log Analytics wrapper
                        LogAnalyticsWrapper logClient = new LogAnalyticsWrapper
                        (
                            workspaceId: configuration.GetSection("LogAnalytics")["WorkspaceId"],
                            sharedKey: configuration.GetSection("LogAnalytics")["SharedKey"],
                            logType: configuration.GetSection("LogAnalytics")["LogType"]
                        );

                        // Construct new audit event
                        AuditEvent auditEvent = new AuditEvent()
                        {
                            UserPrincipalName = User.Identity.Name,
                            ComputerName = searchValue,
                            Action = "SecretGet",
                            CreatedOn = DateTime.UtcNow,
                            Result = "Success",
                            Id = Convert.ToString(secret.SecretId)
                        };

                        // Send audit event
                        await logClient.SendLogEntry(auditEvent);

                        // Populate view with value from Key Vault
                        ViewData["SecretValue"] = secret.SecretValue;
                        ViewData["SecretDeviceName"] = secret.SecretDeviceName;
                        ViewData["SecretDate"] = secret.SecretDate;
                        ViewData["SecretUserName"] = secret.SecretUserName;
                        ViewData["SecretSerialNumber"] = secret.SecretSerialNumber;
                        ViewData["Result"] = "Success";
                    }
                    else
                    {
                        ViewData["Result"] = "Failed";
                    }
                }
                catch (Exception)
                {
                    ViewData["Result"] = "Failed";
                }
            }

            return View();
        }

        public IActionResult Privacy()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}
