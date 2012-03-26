using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Configuration;
using System.Configuration.Provider;
using System.Diagnostics;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.Linq;
using System.Web;
using System.Web.Hosting;
using System.Web.Security;

namespace Ogd.Web.Security
{
    public class LDAPRoleProvider : RoleProvider
    {
        private const string ADFilter = "(&(objectCategory=group)(|(groupType=-2147483646)(groupType=-2147483644)(groupType=-2147483640)))";
        private const string ADField = "samAccountName";

        private string LDAPConnectionString { get; set; }
        private string Domain { get; set; }
        private string ConnectionUsername { get; set; }
        private string ConnectionPassword { get; set; }
        private string ConnectionProtection { get; set; }

        // Retrieve Group Mode
        // "Additive" indicates that only the groups specified in groupsToUse will be used
        // "Subtractive" indicates that all Active Directory groups will be used except those specified in groupsToIgnore
        // "Additive" is somewhat more secure, but requires more maintenance when groups change
        private bool IsAdditiveGroupMode { get; set; }

        private List<string> GroupsToUse { get; set; }
        private List<string> GroupsToIgnore { get; set; }
        private List<string> UsersToIgnore { get; set; }

        #region Ignore Lists

        // IMPORTANT - DEFAULT LIST OF ACTIVE DIRECTORY USERS TO "IGNORE"
        //             DO NOT REMOVE ANY OF THESE UNLESS YOU FULLY UNDERSTAND THE SECURITY IMPLICATIONS
        //             VERYIFY THAT ALL CRITICAL USERS ARE IGNORED DURING TESTING
        private IEnumerable<string> DefaultUsersToIgnore = new[] {
            "Administrator", 
            "TsInternetUser", 
            "Guest", 
            "krbtgt",
            "Replicate",
            "SERVICE", 
            "SMSService"
        };

        // IMPORTANT - DEFAULT LIST OF ACTIVE DIRECTORY DOMAIN GROUPS TO "IGNORE"
        //             PREVENTS ENUMERATION OF CRITICAL DOMAIN GROUP MEMBERSHIP
        //             DO NOT REMOVE ANY OF THESE UNLESS YOU FULLY UNDERSTAND THE SECURITY IMPLICATIONS
        //             VERIFY THAT ALL CRITICAL GROUPS ARE IGNORED DURING TESTING BY CALLING GetAllRoles MANUALLY
        private IEnumerable<string> DefaultGroupsToIgnore = new[] {
            "Domain Guests",
            "Domain Computers",
            "Group Policy Creator Owners", 
            "Guests", 
            "Users",
            "Domain Users",
            "Pre-Windows 2000 Compatible Access",
            "Exchange Domain Servers",
            "Schema Admins",
            "Enterprise Admins",
            "Domain Admins",
            "Cert Publishers",
            "Backup Operators", 
            "Account Operators",
            "Server Operators", 
            "Print Operators",
            "Replicator",
            "Domain Controllers",
            "WINS Users",
            "DnsAdmins",
            "DnsUpdateProxy",
            "DHCP Users", 
            "DHCP Administrators",
            "Exchange Services",
            "Exchange Enterprise Servers", 
            "Remote Desktop Users",
            "Network Configuration Operators",
            "Incoming Forest Trust Builders",
            "Performance Monitor Users",
            "Performance Log Users",
            "Windows Authorization Access Group",
            "Terminal Server License Servers", 
            "Distributed COM Users",
            "Administrators",
            "Everybody",
            "RAS and IAS Servers",
            "MTS Trusted Impersonators",
            "MTS Impersonators",
            "Everyone",
            "LOCAL",
            "Authenticated Users"
        };

        #endregion

        /// <summary>
        /// Initializes a new instance of the LDAPRoleProvider class.
        /// </summary>
        public LDAPRoleProvider()
        {
            GroupsToUse = new List<string>();
            GroupsToIgnore = new List<string>();
            UsersToIgnore = new List<string>();
        }

        public override string ApplicationName { get; set; }

        /// <summary>
        /// Initialize LDAPRoleProvider with config values
        /// </summary>
        /// <param name="name"></param>
        /// <param name="config"></param>
        public override void Initialize(string name, NameValueCollection config)
        {
            if (config == null)
            {
                throw new ArgumentNullException("config");
            }
            else
            {

                if (string.IsNullOrEmpty(name))
                {
                    name = "LDAPRoleProvider";
                }
                DetermineDescription(config);

                // Initialize the abstract base class.
                base.Initialize(name, config);
                DetermineDomain(config);
                DetermineGroupMode(config);
                DetermineConnection(config);

                DetermineApplicationName(config);
                PopulateLists(config);
            }
        }

        private string ReadConfig(NameValueCollection config, string key, bool required = true)
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

        private bool TryReadConfig(NameValueCollection config, string key, out string value)
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

        private void DetermineApplicationName(NameValueCollection config)
        {
            // Retrieve Application Name
            string applicationName;
            if (TryReadConfig(config, "applicationName", out applicationName))
            {
                ApplicationName = applicationName;
            }
            else
            {
                try
                {
                    string app =
                        HostingEnvironment.ApplicationVirtualPath ??
                        Process.GetCurrentProcess().MainModule.ModuleName.Split('.').FirstOrDefault();

                    ApplicationName = app != "" ? app : "/";
                }
                catch
                {
                    ApplicationName = "/";
                }
            }

            if (ApplicationName.Length > 256)
            {
                throw new ProviderException("The application name is too long.");
            }
        }

        private void DetermineDomain(NameValueCollection config)
        {
            Domain = ReadConfig(config, "domain");
        }

        private void DetermineDescription(NameValueCollection config)
        {
            if (string.IsNullOrEmpty(config["description"]))
            {
                config.Remove("description");
                config.Add("description", "Active Directory Role Provider");
            }
        }

        private void DetermineConnection(NameValueCollection config)
        {
            GetConnectionString(config);
            ConnectionProtection = ReadConfig(config, "connectionProtection");
            if (ConnectionProtection.Equals("None", StringComparison.InvariantCultureIgnoreCase))
            {
                ConnectionUsername = ReadConfig(config, "connectionUsername");
                ConnectionPassword = ReadConfig(config, "connectionPassword");
            }
        }

        private void DetermineGroupMode(NameValueCollection config)
        {
            string groupMode;
            TryReadConfig(config, "groupMode", out groupMode);
            IsAdditiveGroupMode = (groupMode == "Additive");
        }

        private void GetConnectionString(NameValueCollection config)
        {
            string ldapConnectionStringName;
            if (TryReadConfig(config, "connectionStringName", out ldapConnectionStringName))
            {
                LDAPConnectionString = ConfigurationManager.ConnectionStrings[ldapConnectionStringName].ConnectionString;
            }
            else
            {
                LDAPConnectionString = ReadConfig(config, "connectionString");
            }
        }

        private void PopulateLists(NameValueCollection config)
        {
            // If Additive group mode, populate GroupsToUse with specified AD groups
            string groupsToUse;
            if (IsAdditiveGroupMode && TryReadConfig(config, "groupsToUse", out groupsToUse))
            {
                GroupsToUse.AddRange(
                    groupsToUse.Split(',').Select(group => group.Trim())
                );
            }

            // Populate GroupsToIgnore List<string> with AD groups that should be ignored for roles purposes
            GroupsToIgnore.AddRange(
                DefaultGroupsToIgnore.Select(group => group.Trim())
            );

            string groupsToIgnore;
            TryReadConfig(config, "groupsToIgnore", out groupsToIgnore);
            GroupsToIgnore.AddRange(
                groupsToIgnore
                    .Split(',')
                    .Select(group => group.Trim())
            );

            // Populate UsersToIgnore ArrayList with AD users that should be ignored for roles purposes
            string usersToIgnore;
            TryReadConfig(config, "usersToIgnore", out usersToIgnore);
            UsersToIgnore.AddRange(
                DefaultUsersToIgnore
                    .Select(value => value.Trim())
                    .Union(
                        usersToIgnore
                            .Split(new[] { "," }, StringSplitOptions.RemoveEmptyEntries)
                            .Select(value => value.Trim())
                    )
            );
        }

        private void RecurseGroup(PrincipalContext context, string group, List<string> groups)
        {
            var principal = GroupPrincipal.FindByIdentity(context, IdentityType.SamAccountName, group);

            if (principal == null)
                return;

            List<string> res = principal
                .GetGroups()
                .Select(grp => grp.Name).ToList();

            groups.AddRange(res.Except(groups));
            foreach (var item in res)
            {
                RecurseGroup(context, item, groups);
            }
        }

        /// <summary>
        /// Retrieve listing of all roles to which a specified user belongs.
        /// </summary>
        /// <param name="username"></param>
        /// <returns>String array of roles</returns>
        public override string[] GetRolesForUser(string username)
        {
            string sessionKey = "groupsForUser:" + username;

            if (HttpContext.Current != null &&
                HttpContext.Current.Session != null &&
                HttpContext.Current.Session[sessionKey] != null)
            {
                return ((List<string>)(HttpContext.Current.Session[sessionKey])).ToArray();
            }

            using (PrincipalContext context = new PrincipalContext(ContextType.Domain, Domain))
            {
                try
                {
                    // add the users groups to the result
                    var groupList = UserPrincipal
                        .FindByIdentity(context, IdentityType.SamAccountName, username)
                        .GetGroups()
                        .Select(group => group.Name)
                        .ToList();

                    // add each groups sub groups into the groupList
                    foreach (var group in new List<string>(groupList))
                    {
                        RecurseGroup(context, group, groupList);
                    }

                    groupList = groupList
                        .Except(GroupsToIgnore)
                        .ToList();

                    if (IsAdditiveGroupMode)
                    {
                        groupList = groupList.Join(GroupsToUse, r => r, g => g, (r, g) => r).ToList();
                    }

                    if (HttpContext.Current != null)
                    {
                        HttpContext.Current.Session[sessionKey] = groupList;
                    }

                    return groupList.ToArray();
                }
                catch (Exception ex)
                {
                    Elmah.ErrorLog.GetDefault(HttpContext.Current).Log(new Elmah.Error(ex, HttpContext.Current));
                    return new[] { "" };
                }
            }
        }

        /// <summary>
        /// Retrieve listing of all users in a specified role.
        /// </summary>
        /// <param name="rolename">String array of users</param>
        /// <returns></returns>
        public override string[] GetUsersInRole(String rolename)
        {
            using (var context = new PrincipalContext(ContextType.Domain, Domain))
            {
                try
                {
                    var groupPrincipal = GroupPrincipal.FindByIdentity(context, IdentityType.SamAccountName, rolename);

                    return groupPrincipal.GetMembers(true)
                        .Where(user => !UsersToIgnore.Contains(user.SamAccountName))
                        .Select(user => user.SamAccountName)
                        .ToArray();
                }
                catch (Exception ex)
                {
                    Elmah.ErrorLog.GetDefault(HttpContext.Current).Log(new Elmah.Error(ex, HttpContext.Current));
                    return new[] { "" };
                }
            }
        }

        /// <summary>
        /// Determine if a specified user is in a specified role.
        /// </summary>
        /// <param name="username"></param>
        /// <param name="rolename"></param>
        /// <returns>Boolean indicating membership</returns>
        public override bool IsUserInRole(string username, string rolename)
        {
            using (var context = new PrincipalContext(ContextType.Domain, Domain))
            {
                try
                {
                    var principal = Principal.FindByIdentity(context, IdentityType.SamAccountName, username);
                    return principal.GetGroups().Any(x => x.SamAccountName.Equals(rolename, StringComparison.InvariantCultureIgnoreCase));
                }
                catch (Exception ex)
                {
                    Elmah.ErrorLog.GetDefault(HttpContext.Current).Log(new Elmah.Error(ex, HttpContext.Current));
                    return false;
                }
            }
        }

        /// <summary>
        /// Retrieve listing of all roles.
        /// </summary>
        /// <returns>String array of roles</returns>
        public override string[] GetAllRoles()
        {
            string[] roles = ADSearch(LDAPConnectionString, ADFilter, ADField);

            return roles.Except(GroupsToIgnore)
                .Where(role => !IsAdditiveGroupMode || GroupsToUse.Contains(role))
                .ToArray();
        }

        /// <summary>
        /// Determine if given role exists
        /// </summary>
        /// <param name="rolename">Role to check</param>
        /// <returns>Boolean indicating existence of role</returns>
        public override bool RoleExists(string rolename)
        {
            return GetAllRoles().Any(role => role == rolename);
        }

        /// <summary>
        /// Return sorted list of usernames like usernameToMatch in rolename
        /// </summary>
        /// <param name="rolename">Role to check</param>
        /// <param name="usernameToMatch">Partial username to check</param>
        /// <returns></returns>
        public override string[] FindUsersInRole(string rolename, string usernameToMatch)
        {
            if (!RoleExists(rolename))
            {
                throw new ProviderException(String.Format("The role '{0}' was not found.", rolename));
            }
            else
            {
                return GetUsersInRole(rolename)
                    .Where(user => user.ToLowerInvariant().Contains(usernameToMatch.ToLowerInvariant()))
                    .ToArray();
            }
        }

        #region Non Supported Base Class Functions

        /// <summary>
        /// AddUsersToRoles not supported.  For security and management purposes, LDAPRoleProvider only supports read operations against Active Direcory. 
        /// </summary>
        public override void AddUsersToRoles(string[] usernames, string[] rolenames)
        {
            throw new NotSupportedException("Unable to add users to roles.  For security and management purposes, LDAPRoleProvider only supports read operations against Active Direcory.");
        }

        /// <summary>
        /// CreateRole not supported.  For security and management purposes, LDAPRoleProvider only supports read operations against Active Direcory. 
        /// </summary>
        public override void CreateRole(string rolename)
        {
            throw new NotSupportedException("Unable to create new role.  For security and management purposes, LDAPRoleProvider only supports read operations against Active Direcory.");
        }

        /// <summary>
        /// DeleteRole not supported.  For security and management purposes, LDAPRoleProvider only supports read operations against Active Direcory. 
        /// </summary>
        public override bool DeleteRole(string rolename, bool throwOnPopulatedRole)
        {
            throw new NotSupportedException("Unable to delete role.  For security and management purposes, LDAPRoleProvider only supports read operations against Active Direcory.");
        }

        /// <summary>
        /// RemoveUsersFromRoles not supported.  For security and management purposes, LDAPRoleProvider only supports read operations against Active Direcory. 
        /// </summary>
        public override void RemoveUsersFromRoles(string[] usernames, string[] rolenames)
        {
            throw new NotSupportedException("Unable to remove users from roles.  For security and management purposes, LDAPRoleProvider only supports read operations against Active Direcory.");
        }

        #endregion

        /// <summary>
        /// Performs an extremely constrained query against Active Directory.  Requests only a single value from
        /// AD based upon the filtering parameter to minimize performance hit from large queries.
        /// </summary>
        /// <param name="ConnectionString">Active Directory Connection String</param>
        /// <param name="filter">LDAP format search filter</param>
        /// <param name="field">AD field to return</param>
        /// <returns>String array containing values specified by 'field' parameter</returns>
        private string[] ADSearch(string ConnectionString, string filter, string field)
        {
            DirectoryEntry directoryEntry;
            if (ConnectionProtection.Equals("None", StringComparison.InvariantCultureIgnoreCase))
            {
                directoryEntry = new DirectoryEntry(ConnectionString, ConnectionUsername, ConnectionPassword);
            }
            else
            {
                directoryEntry = new DirectoryEntry(ConnectionString);
            }
            var searcher = new DirectorySearcher {
                SearchRoot = directoryEntry,
                Filter = filter,
                PageSize = 500
            };
            searcher.PropertiesToLoad.Clear();
            searcher.PropertiesToLoad.Add(field);

            try
            {
                using (var results = searcher.FindAll())
                {
                    List<string> r = new List<string>();
                    foreach (SearchResult searchResult in results)
                    {
                        var prop = searchResult.Properties[field];
                        for (int index = 0; index < prop.Count; index++)
                        {
                            r.Add(prop[index].ToString());
                        }
                    }

                    return r.Count > 0 ? r.ToArray() : new string[0];
                }
            }
            catch (Exception ex)
            {
                throw new ProviderException("Unable to query Active Directory.", ex);
            }
        }
    }
}
