using Azure.Identity;
using Azure.Security.KeyVault.Secrets;
using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace CloudLAPSPortal.Models
{
    public class KeyVaultSecret
    {
        public string SecretDeviceName { get; set; }
        public string SecretValue { get; set; }
        public string SecretDate { get; set; }
        public string SecretId { get; set; }
        public string SecretUserName { get; set; }
        public string SecretSerialNumber { get; set; }

        public static async Task<KeyVaultSecret> GetComputerAsync(string keyVaultUri, string searchValue)
        {
            // Assign empty string to secret variables used to construct a new instance of this class
            string SecretDeviceName = string.Empty;
            string secretValue = string.Empty;
            string secretDate = string.Empty;
            string secretId = string.Empty;
            string secretUserName = string.Empty;
            string secretSerialNumber = string.Empty;

            // Construct secret client for provided key vault using managed system identity for authentication
            var keyVaultClient = new SecretClient(vaultUri: new Uri(keyVaultUri), credential: new DefaultAzureCredential());

            // Search for secret with computer name in Key Vault
            var secretOperation = await keyVaultClient.GetSecretAsync(searchValue);
            var secret = secretOperation.Value;

            try
            {
                SecretDeviceName = secret.Properties.Tags["DeviceName"]?.ToString();
            }
            catch
            {
                // Exception unhandled
            }

            try
            {
                secretValue = secret.Value;
            }
            catch
            {
                // Exception unhandled
            }

            try
            {
                secretDate = secret.Properties.UpdatedOn.ToString();
            }
            catch
            {
                // Exception unhandled
            }

            try
            {
                secretId = secret.Properties.Id.ToString();
            }
            catch
            {
                // Exception unhandled
            }

            try
            {
                secretUserName = secret.Properties.Tags["UserName"]?.ToString();
            }
            catch
            {
                // Exception unhandled
            }

            try
            {
                secretSerialNumber = secret.Properties.Tags["SerialNumber"].ToString();
            }
            catch
            {
                // Exception unhandled
            }

            KeyVaultSecret keyVaultItem = new KeyVaultSecret()
            {
                SecretDeviceName = SecretDeviceName,
                SecretValue = secretValue,
                SecretDate = secretDate,
                SecretId = secretId,
                SecretUserName = secretUserName,
                SecretSerialNumber = secretSerialNumber
            };

            return keyVaultItem;
        }

        public static string TestNotNull(string value)
        {
            return value ?? "";
        }
    }
}
