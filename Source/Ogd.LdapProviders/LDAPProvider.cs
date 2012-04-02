using System;
using System.Collections.Specialized;
using System.Configuration;
using System.Configuration.Provider;
using System.DirectoryServices;
using System.Linq;

namespace Ogd.Web.Security
{
    public class LdapProvider
    {
        internal string LdapConnectionString { get; set; }
        internal string ConnectionUsername { get; set; }
        internal string ConnectionPassword { get; set; }
        internal string ConnectionProtection { get; set; }

        internal static string ReadConfig(NameValueCollection config, string key, bool required = true)
        {
            string value;
            if (TryReadConfig(config, key, out  value) || !required)
            {
                return value;
            }
            else
            {
                throw new ProviderException("Configuration value required for key: " + key);
            }
        }

        internal static bool TryReadConfig(NameValueCollection config, string key, out string value)
        {
            if (config.AllKeys.Any(k => k == key))
            {
                value = config[key];
                return true;
            }
            else
            {
                value = "";
                return false;
            }
        }

        internal void DetermineConnection(NameValueCollection config)
        {
            GetConnectionString(config);
            ConnectionProtection = ReadConfig(config, "connectionProtection");
            if (ConnectionProtection.Equals("None", StringComparison.InvariantCultureIgnoreCase))
            {
                ConnectionUsername = ReadConfig(config, "connectionUsername");
                ConnectionPassword = ReadConfig(config, "connectionPassword");
            }
        }

        private void GetConnectionString(NameValueCollection config)
        {
            string ldapConnectionStringName;
            if (TryReadConfig(config, "connectionStringName", out ldapConnectionStringName))
            {
                LdapConnectionString = ConfigurationManager.ConnectionStrings[ldapConnectionStringName].ConnectionString;
            }
            else
            {
                LdapConnectionString = ReadConfig(config, "connectionString");
            }
        }

        internal DirectoryEntry GetDirectoryEntry()
        {
            DirectoryEntry directoryEntry;
            if (ConnectionProtection.Equals("None", StringComparison.InvariantCultureIgnoreCase))
            {
                directoryEntry = new DirectoryEntry(LdapConnectionString, ConnectionUsername, ConnectionPassword);
            }
            else
            {
                directoryEntry = new DirectoryEntry(LdapConnectionString);
            }
            return directoryEntry;
        }
    }
}
