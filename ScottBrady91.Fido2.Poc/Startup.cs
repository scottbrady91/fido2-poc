using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;

namespace ScottBrady91.Fido2.Poc
{
    public class Startup
    {
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddMvc()
                .SetCompatibilityVersion(CompatibilityVersion.Version_2_1)
                .AddCookieTempDataProvider();

            services.AddAuthentication("cookie")
                .AddCookie("cookie");
        }
        
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            app.UseDeveloperExceptionPage();

            app.UseAuthentication();

            app.UseStaticFiles();
            app.UseMvcWithDefaultRoute();
        }
    }
}
