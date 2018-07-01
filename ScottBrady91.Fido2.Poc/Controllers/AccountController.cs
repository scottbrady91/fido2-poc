using Microsoft.AspNetCore.Mvc;

namespace ScottBrady91.Fido2.Poc.Controllers
{
    public class AccountController : Controller
    {
        public IActionResult Login()
        {
            return View();
        }

        public IActionResult Register()
        {
            return View();
        }
    }
}