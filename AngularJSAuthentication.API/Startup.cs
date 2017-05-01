using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Http;
using AngularJSAuthentication.API.Providers;
using Microsoft.Owin;
using Microsoft.Owin.Cors;
using Microsoft.Owin.Security.OAuth;
using Owin;

[assembly: OwinStartup(typeof(AngularJSAuthentication.API.Startup))]
namespace AngularJSAuthentication.API
{
    public class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            // configure our API to use OAuth authentication workflow
            ConfigureOAuth(app);

            // configure API routes
            HttpConfiguration config = new HttpConfiguration();
            WebApiConfig.Register(config);
            // Allow CORS for ASP.NET Web API
            app.UseCors(CorsOptions.AllowAll);
            // wire up ASP.NET Web API to Owin server pipeline
            app.UseWebApi(config);
        }

        public void ConfigureOAuth(IAppBuilder app)
        {
            OAuthAuthorizationServerOptions OAuthServerOptions = new OAuthAuthorizationServerOptions()
            {
                AllowInsecureHttp = true,
                TokenEndpointPath = new PathString("/token"),
                AccessTokenExpireTimeSpan = TimeSpan.FromDays(1),
                Provider = new SimpleAuthorizationServerProvider()
            };

            // Token Generation - add the authentication middleware to the pipeline
            app.UseOAuthAuthorizationServer(OAuthServerOptions);
            app.UseOAuthBearerAuthentication(new OAuthBearerAuthenticationOptions());

        }
    }
}