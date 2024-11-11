using IdentityApp.Models;
using IdentityApp.ViewModels;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace IdentityApp.Controllers
{
    public class AccountController : Controller
    {

         private UserManager<AppUser> _userManager;
        private RoleManager<AppRole> _roleManager;
        private SignInManager<AppUser> _signInManager;
        private IEmailSender _emailSender; 
        public AccountController(
            UserManager<AppUser> userManager,
            RoleManager<AppRole> roleManager,
            SignInManager<AppUser> signInManager,
            IEmailSender emailSender
            )
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _signInManager = signInManager;
            _emailSender = emailSender;
        }
        public IActionResult Login()
        {
            return View();
        }

        [HttpPost]

        public async Task<IActionResult> Login(LoginViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(model.Email);

                if (user != null)
                {
                    await _signInManager.SignOutAsync();

                    if (!await _userManager.IsEmailConfirmedAsync(user))
                    {
                        ModelState.AddModelError("","Hesabinizi onaylayin");
                        return View(model);   
                    }
                    var result = await _signInManager.PasswordSignInAsync(user,model.Password,model.RememberMe,true);

                    if (result.Succeeded)
                    {
                        await _userManager.ResetAccessFailedCountAsync(user);
                        await _userManager.SetLockoutEndDateAsync(user,null);

                        return RedirectToAction("Index","Home");
                        
                    }
                    else if (result.IsLockedOut) 
                    {
                        var lockoutDate = await _userManager.GetLockoutEndDateAsync(user);
                        var timeLeft = lockoutDate.Value - DateTime.UtcNow;
                        ModelState.AddModelError("", $"Hesabiniz kitlendi,Lutfen {timeLeft.Minutes+1} dakika sonra tekrar deneyin");
                    }
                    else 
                    {
                        ModelState.AddModelError(string.Empty, "hatali  parola");
                    }
                }
                else
                {
                    ModelState.AddModelError(string.Empty, "bu email ile hesab bulunamadi");
                }
            }
            return View(model);
        }


        public IActionResult Create()
        {
            return View();
        }
        [HttpPost]
        public async Task<IActionResult> Create(CreateViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = new AppUser{UserName = model.UserName,Email=model.Email,FullName = model.FullName};

                IdentityResult result = await _userManager.CreateAsync(user, model.Password);

                if (result.Succeeded)
                {
                    var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                    var url = Url.Action("ConfirmEmail", "Account",new {
                        user.Id, token
                    });

                    await _emailSender.SendEmailAsync(user.Email,"Hesab Onayi",$"Lutfen email hesabinizi onaylamak icin linke  <a href='http://localhost:5034{url}'>tiklayiniz<a/>");
                    TempData["message"] = "Email hesabinizdaki onay mailine tiklayiniz";
                    return RedirectToAction("Login","Account");
                }

                foreach (IdentityError item in result.Errors)
                {
                    ModelState.AddModelError("",item.Description);
                }
            }
            return View(model);
        }

        public async Task<IActionResult> ConfirmEmail(string id,string token)
        {
            if (id == null || token == null) 
            {
                TempData["message"] = "Gecersiz token bilgisi";
                return View();
            }

            var user = await _userManager.FindByIdAsync(id);
            if (user !=null)
            {
                var result = await _userManager.ConfirmEmailAsync(user, token);

                if (result.Succeeded)
                {
                    TempData["message"] = "Hesabiniz onaylandi";
                    return RedirectToAction("Login","Account");
                }
            }

            TempData["message"] = "Kullanici Bulunamadi";
            return View("ConfirmEmail");
        }


        public async Task<IActionResult> Logout()
        {
            await _signInManager.SignOutAsync();
            return RedirectToAction("Login"); 
        }

        public  IActionResult ForgotPassword()
        {
            return View(); 
        }

        [HttpPost]
        public async Task<IActionResult> ForgotPassword(string Email)
        {
            if (string.IsNullOrEmpty(Email))
            {
                TempData["message"] = "Email adresinizi giriniz";
                return View(); 
            }

            var user = await _userManager.FindByEmailAsync(Email);
            if (user == null)
            {
                TempData["message"] = "Email ile eslesen kayit yok";
                return View(); 
            }

            var token = await _userManager.GeneratePasswordResetTokenAsync(user);

            var url = Url.Action("ResetPassword", "Account",new {user.Id, token});

            await _emailSender.SendEmailAsync(Email, "Parola Sifirlama",$"Parolanizi Yenilemek Linke tiklayiniz <a href='http://localhost:5034{url}'>tiklayiniz<a/>");

            TempData["message"] = "Eposta adresinize gonderilen link ile sifrenizi sifirlayabilirsizin";

            return View();
        }

        public IActionResult ResetPassword(string Id,string token)
        {
            if (Id ==null || token ==null)
            {
                return RedirectToAction("Login");
            }

            var model = new ResetPasswordViewModel{Token = token};
            return View(model);
        }  


        [HttpPost]
        public async Task<IActionResult> ResetPassword(ResetPasswordViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(model.Email);
                if (user == null)
                {
                    TempData["message"] = "Bu email adresi ile kullanici yok";
                    return RedirectToAction("Login");
                }
                var result = await _userManager.ResetPasswordAsync(user,model.Token,model.Password);
                if (result.Succeeded)
                {
                    TempData["message"] = "Sifreniz Degistirildi";
                    return RedirectToAction("Login");
                }
                foreach (IdentityError item in result.Errors)
                {
                    ModelState.AddModelError("",item.Description);
                }  
            }
            return View(model);
        }

        



    }
}