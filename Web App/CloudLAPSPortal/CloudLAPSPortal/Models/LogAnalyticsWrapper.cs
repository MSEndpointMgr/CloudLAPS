using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace CloudLAPSPortal.Models
{
    public class LogAnalyticsWrapper
    {
        // Modified source code class from: https://zimmergren.net/building-custom-data-collectors-for-azure-log-analytics/

        private string WorkspaceId { get; }
        private string SharedKey { get; }
        private string LogType { get; }
        private string RequestBaseUrl { get; }

        // You might want to implement your own disposing patterns, or use a static httpClient instead. Use cases vary depending on how you'd be using the code.
        private readonly HttpClient httpClient;

        public LogAnalyticsWrapper(string workspaceId, string sharedKey, string logType)
        {
            if (string.IsNullOrEmpty(workspaceId))
                throw new ArgumentNullException(nameof(workspaceId), "workspaceId cannot be null or empty");

            if (string.IsNullOrEmpty(sharedKey))
                throw new ArgumentNullException(nameof(sharedKey), "sharedKey cannot be null or empty");

            if (string.IsNullOrEmpty(logType))
                throw new ArgumentNullException(nameof(logType), "logType cannot be null or empty");

            WorkspaceId = workspaceId;
            SharedKey = sharedKey;
            LogType = logType;
            RequestBaseUrl = $"https://{WorkspaceId}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01";

            httpClient = new HttpClient();
        }

        public async Task SendLogEntry<T>(T entity)
        {
            #region Argument validation

            if (entity == null)
                throw new NullReferenceException("parameter 'entity' cannot be null");

            if (LogType.Length > 100)
                throw new ArgumentOutOfRangeException(nameof(LogType), LogType.Length, "The size limit for this parameter is 100 characters.");

            if (!IsAlphaOnly(LogType))
                throw new ArgumentOutOfRangeException(nameof(LogType), LogType, "Log-Type can only contain alpha characters. It does not support numerics or special characters.");

            ValidatePropertyTypes(entity);

            #endregion

            List<T> list = new List<T> { entity };
            await SendLogEntries(list, LogType).ConfigureAwait(false);
        }

        public async Task SendLogEntries<T>(List<T> entities, string logType)
        {
            #region Argument validation

            if (entities == null)
                throw new NullReferenceException("parameter 'entities' cannot be null");

            if (logType.Length > 100)
                throw new ArgumentOutOfRangeException(nameof(logType), logType.Length, "The size limit for this parameter is 100 characters.");

            if (!IsAlphaOnly(logType))
                throw new ArgumentOutOfRangeException(nameof(logType), logType, "Log-Type can only contain alpha characters. It does not support numerics or special characters.");

            foreach (var entity in entities)
                ValidatePropertyTypes(entity);

            #endregion

            var dateTimeNow = DateTime.UtcNow.ToString("r");

            var entityAsJson = JsonConvert.SerializeObject(entities);
            var authSignature = GetAuthSignature(entityAsJson, dateTimeNow);

            httpClient.DefaultRequestHeaders.Clear();
            httpClient.DefaultRequestHeaders.Add("Authorization", authSignature);
            httpClient.DefaultRequestHeaders.Add("Log-Type", logType);
            httpClient.DefaultRequestHeaders.Add("Accept", "application/json");
            httpClient.DefaultRequestHeaders.Add("x-ms-date", dateTimeNow);
            httpClient.DefaultRequestHeaders.Add("time-generated-field", ""); // if we want to extend this in the future to support custom date fields from the entity etc.

            HttpContent httpContent = new StringContent(entityAsJson, Encoding.UTF8);
            httpContent.Headers.ContentType = new MediaTypeHeaderValue("application/json");
            HttpResponseMessage response = await httpClient.PostAsync(new Uri(RequestBaseUrl), httpContent).ConfigureAwait(false);

            HttpContent responseContent = response.Content;
            string result = await responseContent.ReadAsStringAsync().ConfigureAwait(false);
            // helpful todo: if you want to return the data, this might be a good place to start working with it...
        }

        #region Helpers
        private string GetAuthSignature(string serializedJsonObject, string dateString)
        {
            string stringToSign = $"POST\n{serializedJsonObject.Length}\napplication/json\nx-ms-date:{dateString}\n/api/logs";
            string signedString;

            var encoding = new ASCIIEncoding();
            var sharedKeyBytes = Convert.FromBase64String(SharedKey);
            var stringToSignBytes = encoding.GetBytes(stringToSign);
            using (var hmacsha256Encryption = new HMACSHA256(sharedKeyBytes))
            {
                var hashBytes = hmacsha256Encryption.ComputeHash(stringToSignBytes);
                signedString = Convert.ToBase64String(hashBytes);
            }

            return $"SharedKey {WorkspaceId}:{signedString}";
        }
        private bool IsAlphaOnly(string str)
        {
            return Regex.IsMatch(str, @"^[a-zA-Z]+$");
        }
        private void ValidatePropertyTypes<T>(T entity)
        {
            // as of 2018-10-30, the allowed property types for log analytics, as defined here (https://docs.microsoft.com/en-us/azure/log-analytics/log-analytics-data-collector-api#record-type-and-properties) are: string, bool, double, datetime, guid.
            // anything else will be throwing an exception here.
            foreach (PropertyInfo propertyInfo in entity.GetType().GetProperties())
            {
                if (propertyInfo.PropertyType != typeof(string) &&
                    propertyInfo.PropertyType != typeof(bool) &&
                    propertyInfo.PropertyType != typeof(double) &&
                    propertyInfo.PropertyType != typeof(DateTime) &&
                    propertyInfo.PropertyType != typeof(Guid))
                {
                    throw new ArgumentOutOfRangeException($"Property '{propertyInfo.Name}' of entity with type '{entity.GetType()}' is not one of the valid properties. Valid properties are String, Boolean, Double, DateTime, Guid.");
                }
            }
        }
        #endregion
    }
}
