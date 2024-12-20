using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using IdentityManager.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;

namespace IdentityManager.Controllers;

public class HomeController : Controller
{
    private readonly ILogger<HomeController> _logger;
    private readonly UserManager<ApplicationUser> _userManager;

    public HomeController(ILogger<HomeController> logger, UserManager<ApplicationUser> userManager)
    {
        _logger = logger;
        _userManager = userManager;
    }

    public async Task<IActionResult> Index()
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null)
        {
            ViewBag.TwoFactorEnabled = false;
        }
        else
        {
            ViewBag.TwoFactorEnabled = user.TwoFactorEnabled;
        }
        return View();
    }

    [Authorize(Roles = SD.Admin)]
    public IActionResult Privacy()
    {
        return View();
    }

    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    public IActionResult Error()
    {
        return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
    }
}
