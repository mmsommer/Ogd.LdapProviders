using System;
using System.Collections.Specialized;
using System.DirectoryServices.AccountManagement;
using System.Web;
using System.Web.Security;

namespace Ogd.Web.Security
{
    public class LdapMembershipProvider : ActiveDirectoryMembershipProvider
    {
        private LdapProvider LdapProvider { get; set; }

        public LdapMembershipProvider()
        {
            LdapProvider = new LdapProvider();
        }

        public override void Initialize(string name, NameValueCollection config)
        {
            if (config == null)
            {
                throw new ArgumentNullException("config");
            }
            else
            {
                base.Initialize(name, config);
                LdapProvider.DetermineDomain(config);
                LdapProvider.DetermineConnection(config);
            }
        }

        public string GetDisplayName(string username)
        {
            using (var context = new PrincipalContext(ContextType.Domain, LdapProvider.Domain))
            {
                try
                {
                    var principal = UserPrincipal.FindByIdentity(context, IdentityType.SamAccountName, username);
                    return principal.DisplayName;
                }
                catch (Exception ex)
                {
                    Elmah.ErrorLog.GetDefault(HttpContext.Current).Log(new Elmah.Error(ex, HttpContext.Current));
                    return "";
                }
            }
        }

        private string ReadConfig(NameValueCollection config, string key, bool required = true)
        {
            return LdapProvider.ReadConfig(config, key, required);
        }

        private bool TryReadConfig(NameValueCollection config, string key, out string value)
        {
            return LdapProvider.TryReadConfig(config, key, out value);
        }

        #region Non Supported Base Class Functions

        public override bool ChangePassword(string username, string oldPassword, string newPassword)
        {
            throw new NotSupportedException("Unable to change passwords of users. For security and management purposes, LDAPMembershipProvider only supports read operations against Active Direcory.");
        }

        public override bool ChangePasswordQuestionAndAnswer(
            string username,
            string password,
            string newPasswordQuestion,
            string newPasswordAnswer
        )
        {
            throw new NotSupportedException("Unable to change password question and answer of users. For security and management purposes, LDAPMembershipProvider only supports read operations against Active Direcory.");
        }

        public override MembershipUser CreateUser(
            string username,
            string password,
            string email,
            string passwordQuestion,
            string passwordAnswer,
            bool isApproved,
            object providerUserKey,
            out MembershipCreateStatus status
        )
        {
            throw new NotSupportedException("Unable to create users. For security and management purposes, LDAPMembershipProvider only supports read operations against Active Direcory.");
        }

        public override bool DeleteUser(string username, bool deleteAllRelatedData)
        {
            throw new NotSupportedException("Unable to delete users. For security and management purposes, LDAPMembershipProvider only supports read operations against Active Direcory.");
        }

        public override string ResetPassword(string username, string passwordAnswer)
        {
            throw new NotSupportedException("Unable to reset passwords of users. For security and management purposes, LDAPMembershipProvider only supports read operations against Active Direcory.");
        }

        public override bool UnlockUser(string username)
        {
            throw new NotSupportedException("Unable to unlock users. For security and management purposes, LDAPMembershipProvider only supports read operations against Active Direcory.");
        }

        public override void UpdateUser(MembershipUser user)
        {
            throw new NotSupportedException("Unable to update users. For security and management purposes, LDAPMembershipProvider only supports read operations against Active Direcory.");
        }

        #endregion
    }
}
