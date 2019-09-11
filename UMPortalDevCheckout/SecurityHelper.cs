using IdentityModel;
using IdentityModel.Client;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;



namespace AHM.UMPortal.Common
{
    public static class SecurityHelper
    {

        public static void Login()
        {

        }


        public static ClaimsPrincipal GeneratePrincipalFromJWTSecurityToken(string protectedText, IConfiguration configuration)
        {

            var handler = new JwtSecurityTokenHandler();
            ClaimsPrincipal principal = null;
            SecurityToken validToken = null;

            var validIssuer = configuration.GetSection("IdentityServerSetting:AATokenIssuer").Value;
            var validAudience = configuration.GetSection("IdentityServerSetting:AATokenAudience").Value;
            var validClockSkew = configuration.GetSection("IdentityServerSetting:AATokenClockSkew").Value;
            var validThumbPrint = configuration.GetSection("IdentityServerSetting:SigningCertThumbPrint").Value;

            double clockSkew = 30.0;
            double.TryParse(validClockSkew, out clockSkew);

            var tokenValidationParameters = new TokenValidationParameters
           {
                // The signing key must match!
                ValidateIssuerSigningKey = true,
                IssuerSigningKey =  new X509SecurityKey(GetSigningCertificate(validThumbPrint)),

                // Validate the JWT Issuer (iss) claim
                ValidateIssuer = true,
                ValidIssuer = validIssuer,

                // Validate the JWT Audience (aud) claim
                ValidateAudience = true,
                ValidAudience = validAudience,

                // Validate the token expiry
                ValidateLifetime = false,

                // If you want to allow a certain amount of clock drift, set that here:
                ClockSkew = TimeSpan.FromSeconds(clockSkew),

               TokenDecryptionKey = CreateCertificateEncryptionCredentials(validThumbPrint).Key,

               RequireSignedTokens = true

           };

            principal = handler.ValidateToken(protectedText, tokenValidationParameters, out validToken);

            var validJwt = validToken as JwtSecurityToken;

            if (validJwt == null)
            {
                throw new ArgumentException("Invalid JWT");
            }

            if (!validJwt.Header.Enc.Equals("A256CBC-HS512", StringComparison.Ordinal))
            {
                throw new ArgumentException($"Encrption algorithm must be 'A256CBC-HS512'");
            }

            if (!validJwt.Header.Alg.Equals("RSA-OAEP", StringComparison.Ordinal))
            {
                throw new ArgumentException($"Signing algorithm must be 'RSA-OAEP'");
            }

            return principal;
        }


        public static async Task<ClaimsPrincipal> GeneratePrincipalFromIdSrvAccessToken(string jwt, string identityServerUrl, string resourceAPIName)
        {
            ClaimsPrincipal principal = null;
            SecurityToken validToken = null;
            try
            {
                // read discovery document to find issuer and key material
                var disco = await DiscoveryClient.GetAsync(identityServerUrl);

                var keys = new List<SecurityKey>();
                foreach (var webKey in disco.KeySet.Keys)
                {
                    var e = Base64Url.Decode(webKey.E);
                    var n = Base64Url.Decode(webKey.N);

                    var key = new RsaSecurityKey(new RSAParameters { Exponent = e, Modulus = n })
                    {
                        KeyId = webKey.Kid
                    };

                    keys.Add(key);
                }

                var parameters = new TokenValidationParameters
                {
                    ValidIssuer = disco.Issuer,
                    ValidAudience = resourceAPIName,
                    IssuerSigningKeys = keys,
                    NameClaimType = JwtClaimTypes.Name,
                    RoleClaimType = JwtClaimTypes.Role
                };

                var handler = new JwtSecurityTokenHandler();
                handler.InboundClaimTypeMap.Clear();

                principal = handler.ValidateToken(jwt, parameters, out validToken);
                var validJwt = validToken as JwtSecurityToken;

                if (validJwt == null)
                {
                    throw new ArgumentException("Invalid JWT");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                throw new ArgumentException("Invalid JWT");
            }
            return principal;
        }

        private static X509Certificate2 GetSigningCertificate(string SigningCertThumbprint)
        {
            X509Certificate2 cert = null;
            //string SigningCertName = "umportalidsign.ahmcert.com.p12";
            //string SigningCertPwd = "Welcome$009";
           // string SigningCertThumbprint = "526C859D2A59FAE7933A41357458C674E2DE4B72";

            using (X509Store certStore = new X509Store(StoreName.Root, StoreLocation.LocalMachine))
            {
                certStore.Open(OpenFlags.ReadOnly);
                X509Certificate2Collection certCollection = certStore.Certificates.Find(
                    X509FindType.FindByThumbprint,
                   SigningCertThumbprint, false);

                // Get the first cert with the thumbprint
                if (certCollection.Count > 0)
                {
                    cert = certCollection[0];
                }
            }
            return cert;
        }

        public static EncryptingCredentials CreateCertificateEncryptionCredentials(string validThumbPrint)
        {
            return new EncryptingCredentials(new X509SecurityKey(GetSigningCertificate(validThumbPrint)), SecurityAlgorithms.RsaOAEP, SecurityAlgorithms.Aes256CbcHmacSha512);
        }

    }
}
