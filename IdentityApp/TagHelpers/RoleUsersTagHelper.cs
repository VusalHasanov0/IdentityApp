using IdentityApp.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Razor.TagHelpers;

namespace IdentityApp.TagHelpers
{
    [HtmlTargetElement("td",Attributes = "asp-role-users")]
    public class RoleUsersTagHelpers : TagHelper
    {
        private readonly RoleManager<AppRole> _rolemanager;
        private readonly UserManager<AppUser> _usermanager;

        public RoleUsersTagHelpers(RoleManager<AppRole> rolemanager,UserManager<AppUser> usermanager)
        {
            _rolemanager = rolemanager;
            _usermanager = usermanager;
        }

        
        [HtmlAttributeName("asp-role-users")]
        public string RoleId { get; set; } = null!;

        public override  async Task ProcessAsync(TagHelperContext context, TagHelperOutput output)
        {
            var userNames = new List<string>();
            var role = await _rolemanager.FindByIdAsync(RoleId);

            if (role != null && role.Name != null)
            {
                foreach (var user in _usermanager.Users)
                {
                    if (await _usermanager.IsInRoleAsync(user,role.Name))
                    {
                        userNames.Add(user.UserName ?? "");
                    }
                }
                output.Content.SetHtmlContent(userNames.Count == 0 ? "Kullanici Yok" : setHtml(userNames));
            }

        }

        private string setHtml(List<string> userNames)
        {
            var html = "<ul>";
            foreach (var user in userNames)
            {
                html += "<li>"+ user + "</li>";
            }
            html += "</ul>";
            return html;
        }
    }   
}