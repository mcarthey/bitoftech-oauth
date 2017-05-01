using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.Owin.Security.OAuth;

namespace AngularJSAuthentication.API.Providers
{
    public class SimpleAuthorizationServerProvider : OAuthAuthorizationServerProvider
    {
        /// <summary>
        /// Responsible for validating the “Client”, in our case we have only one client so we’ll always return that its validated successfully
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        public override async Task ValidateClientAuthentication(OAuthValidateClientAuthenticationContext context)
        {
            context.Validated();
        }

        /// <summary>
        /// Responsible to validate the username and password sent to the authorization server’s token endpoint, 
        /// so we’ll use the “AuthRepository” class we created earlier and call the method “FindUser” to check 
        /// if the username and password are valid
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        public override async Task GrantResourceOwnerCredentials(OAuthGrantResourceOwnerCredentialsContext context)
        {
            // allow CORS on the token middleware provider - if you forget this, generating the token will fail when you try to call it from your browser
            // Note this only allows CORS for token middleware provider not for ASP.NET Web API
            context.OwinContext.Response.Headers.Add("Access-Control-Allow-Origin", new[] { "*" });

            using (AuthRepository _repo = new AuthRepository())
            {
                IdentityUser user = await _repo.FindUser(context.UserName, context.Password);

                if (user == null)
                {
                    context.SetError("invalid_grant", "The user name or password is incorrect.");
                    return;
                }
            }

            var identity = new ClaimsIdentity(context.Options.AuthenticationType);
            // JWT Claims
            // https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-token-and-claims
            // sub
            // Subject Identifies the principal about which the token asserts information, such as the user of an application. 
            // This value is immutable and cannot be reassigned or reused, so it can be used to perform authorization checks safely.
            // Because the subject is always present in the tokens the Azure AD issues, we recommended using this value in a 
            // general purpose authorization system.
            identity.AddClaim(new Claim("sub", context.UserName));
            // roles
            // Represents all application roles that the subject has been granted both directly and indirectly through group membership 
            // and can be used to enforce role-based access control. Application roles are defined on a per - application basis, 
            // through the appRoles property of the application manifest. The value property of each application role is the value that 
            // appears in the roles claim.
            identity.AddClaim(new Claim("role", "user"));

            // generate the token behind the scenes
            context.Validated(identity);

        }
    }
}