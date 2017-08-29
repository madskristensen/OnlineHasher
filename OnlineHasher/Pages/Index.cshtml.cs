using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using System.Security.Cryptography;
using System.Text;

namespace OnlineHasher.Pages
{
    public class IndexModel : PageModel
    {
        public string Hash { get; set; }

        public void OnGet([FromQuery] string password, [FromQuery] string salt)
        {
            if (!string.IsNullOrEmpty(password))
            {
                byte[] saltBytes = string.IsNullOrWhiteSpace(salt) ? new byte[0] : Encoding.UTF8.GetBytes(salt);

                byte[] hashBytes = KeyDerivation.Pbkdf2(
                    password: password,
                    salt: saltBytes,
                    prf: KeyDerivationPrf.HMACSHA1,
                    iterationCount: 1000,
                    numBytesRequested: 256 / 8
                );

                Hash = BitConverter.ToString(hashBytes).Replace("-", string.Empty);
            }
        }
    }
}
