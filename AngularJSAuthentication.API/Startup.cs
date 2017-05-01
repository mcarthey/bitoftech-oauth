using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Http;
using Microsoft.Owin;
using Owin;

[assembly: OwinStartup(typeof(AngularJSAuthentication.API.Startup))]
namespace AngularJSAuthentication.API
{
    public class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            // configure API routes
            HttpConfiguration config = new HttpConfiguration();
            WebApiConfig.Register(config);
            // wire up ASP.NET Web API to Owin server pipeline
            app.UseWebApi(config);
        }
    }
}