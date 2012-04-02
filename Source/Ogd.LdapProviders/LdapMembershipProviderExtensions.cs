using System;
using System.DirectoryServices.AccountManagement;
using System.Web;
using System.Web.Security;

namespace Ogd.Web.Security
{
    public static class LdapMembershipProviderExtensions
    {
        public static string GetDisplayName(this MembershipUser user)
        {
            return user.UserName.GetDisplayName();
        }

        public static string GetDisplayName(this string username)
        {
            try
            {
                using (var context = new PrincipalContext(ContextType.Domain))
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
            catch (PrincipalServerDownException ex)
            {
                Elmah.ErrorLog.GetDefault(HttpContext.Current).Log(new Elmah.Error(ex, HttpContext.Current));
                return username;
            }
        }
    }
}
